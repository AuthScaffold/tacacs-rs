"""Check generated defaults and structural reuse for policy containers."""

import io
import re
import tempfile
import unittest

from pyang import context, repository
from plugins.yang2rust import Collector, RustEmitter


class GeneratedDefaultsTests(unittest.TestCase):
    def test_choice_constant_names_do_not_collide_with_paths_or_metadata(self):
        output = self.generate('''
container identity {
    choice source {
        case reference {
            choice reference-auth-type { leaf reference { type string; } }
        }
        case explicit {
            choice auth-type { leaf certificate { type string; } }
        }
    }
    choice source-explicit-auth-type { leaf fallback { type string; } }
    choice source-explicit-auth-type-2 { leaf alternative { type string; } }
    choice source-path { leaf location { type string; } }
}
''')
        constants = re.findall(r'pub const (CHOICE_\w+):', output)
        self.assertEqual(len(constants), len(set(constants)), constants)
        self.assertEqual(len(constants), 24)
        self.assertIn('"source/reference/reference-auth-type";', output)
        self.assertIn('"source/explicit/auth-type";', output)
        self.assertIn('"source-explicit-auth-type";', output)
        self.assertIn('"source-path";', output)
        self.assertIn('&[("source", "reference")];', output)
        self.assertIn('&[("source", "explicit")];', output)
        self.assertIn('("reference", &["reference"]),', output)
        self.assertIn('("explicit", &["certificate"]),', output)

    def test_nested_mandatory_choice_retains_parent_case_activation(self):
        output = self.generate('''
container identity {
    choice source {
        case reference { leaf reference { type string; } }
        case explicit {
            leaf label { type string; }
            choice auth-type {
                mandatory true;
                case cert { leaf certificate { type string; } }
                case epsk { leaf tls13-epsk { type string; } }
            }
        }
    }
}
''')
        self.assertIn(
            '("explicit", &["label", "certificate", "tls13-epsk"]),', output
        )
        self.assertIn('pub const CHOICE_SOURCE_EXPLICIT_AUTH_TYPE:', output)
        self.assertIn('CHOICE_SOURCE_EXPLICIT_AUTH_TYPE_MANDATORY: bool = true;', output)
        self.assertIn(
            'CHOICE_SOURCE_EXPLICIT_AUTH_TYPE_ACTIVATION: &[(&str, &str)] = '
            '&[("source", "explicit")];', output
        )
        self.assertIn('("cert", &["certificate"]),', output)
        self.assertIn('("epsk", &["tls13-epsk"]),', output)

    def test_choice_constraints_keep_distinct_structures(self):
        for nested in [False, True]:
            with self.subTest(nested=nested):
                choice = '''choice auth-type {
                    mandatory %s;
                    case cert { leaf certificate { type string; } }
                    case epsk { leaf tls13-epsk { type string; } }
                }'''
                if nested:
                    choice = 'choice source { case explicit { ' + choice + ' } }'
                output = self.generate(
                    'container optional { ' + choice % 'false' + ' }'
                    'container required { ' + choice % 'true' + ' }'
                )
                self.assertIn('pub struct Optional', output)
                self.assertIn('pub struct Required', output)
                name = 'SOURCE_EXPLICIT_AUTH_TYPE' if nested else 'AUTH_TYPE'
                self.assertIn(f'CHOICE_{name}_MANDATORY: bool = false;', output)
                self.assertIn(f'CHOICE_{name}_MANDATORY: bool = true;', output)

    def test_case_membership_keeps_distinct_structures(self):
        output = self.generate('''
container first {
    choice selector { case one { leaf a { type string; } leaf b { type string; } } }
}
container second {
    choice selector { case one { leaf a { type string; } } }
    leaf b { type string; }
}
''')
        self.assertIn('pub struct First', output)
        self.assertIn('pub struct Second', output)
        self.assertIn('("one", &["a", "b"]),', output)
        self.assertIn('("one", &["a"]),', output)

    def test_default_delimiters_keep_distinct_structures(self):
        output = self.generate('''
container first {
    choice selector {
        case one {
            leaf a { type string; default "x:M:false]]|L:b:string:D:y"; }
        }
    }
    leaf b { type string; default "z"; }
}
container second {
    choice selector {
        case one { leaf a { type string; default "x"; } }
    }
    leaf b { type string; default "y:M:false]]|L:b:string:D:z"; }
}
''')
        self.assertIn('pub struct First', output)
        self.assertIn('pub struct Second', output)
        self.assertIn('"z".to_owned()', output)
        self.assertIn('"y:M:false]]|L:b:string:D:z".to_owned()', output)

    def test_nested_choices_retain_full_activation_paths(self):
        output = self.generate('''
container identity {
    choice source {
        case explicit {
            choice auth-type {
                case cert {
                    choice key-type {
                        mandatory true;
                        leaf private-key { type string; }
                    }
                }
                case epsk {
                    choice symmetric-type { leaf symmetric-key { type string; } }
                }
            }
        }
    }
}
''')
        self.assertIn(
            'CHOICE_SOURCE_EXPLICIT_AUTH_TYPE_CERT_KEY_TYPE_PATH: &str = '
            '"source/explicit/auth-type/cert/key-type";', output
        )
        self.assertIn(
            'CHOICE_SOURCE_EXPLICIT_AUTH_TYPE_CERT_KEY_TYPE_ACTIVATION: '
            '&[(&str, &str)] = &[("source", "explicit"), '
            '("source/explicit/auth-type", "cert")];', output
        )
        self.assertIn('pub const CHOICE_SOURCE_EXPLICIT_AUTH_TYPE_EPSK_SYMMETRIC_TYPE:', output)

    def test_binary_leaf_list_in_choice_uses_optional_list_serializer(self):
        output = self.generate('''
container evidence {
    choice source {
        mandatory true;
        case inline { leaf-list crl { type binary; min-elements 1; } }
        case provider { leaf reference { type string; } }
    }
}
''')
        self.assertIn('pub crl: Option<Vec<Vec<u8>>>', output)
        self.assertIn('base64_binary::option_vec_bytes', output)

    def test_project_containers_and_lists_use_qualified_json_names(self):
        with tempfile.TemporaryDirectory() as directory:
            ctx = context.Context(repository.FileRepository(directory))
            base = ctx.add_module("policy.yang", '''
module policy {
    yang-version 1.1;
    namespace "urn:test:policy";
    prefix p;
    container auth;
}
''')
            ctx.add_module("tacacsrs.yang", '''
module tacacsrs {
    yang-version 1.1;
    namespace "urn:test:tacacsrs";
    prefix trs;
    import policy { prefix p; }
    augment "/p:auth" {
        container evidence { leaf age { type uint32; } }
        list sources { key name; leaf name { type string; } }
    }
}
''')
            ctx.validate()
            self.assertEqual(ctx.errors, [])
            collector = Collector(ctx)
            collector.collect_module(base)
            output = io.StringIO()
            RustEmitter(output, collector).emit()
            self.assertIn('serde(rename = "tacacsrs:evidence")', output.getvalue())
            self.assertIn('serde(rename = "tacacsrs:sources")', output.getvalue())

    def test_empty_leaves_use_presence_type_without_sibling_import(self):
        output = self.generate("container auth { leaf present { type empty; } }")
        self.assertIn("Option<crate::YangEmpty>", output)
        self.assertIn("deserialize_present_empty", output)
        self.assertNotIn("use super::crate;", output)

    def generate(self, body):
        with tempfile.TemporaryDirectory() as directory:
            ctx = context.Context(repository.FileRepository(directory))
            module = ctx.add_module("policy.yang", f"""
module policy {{
    yang-version 1.1;
    namespace "urn:test:policy";
    prefix p;
    {body}
}}
""")
            ctx.validate()
            self.assertEqual(ctx.errors, [])
            collector = Collector(ctx)
            collector.collect_module(module)
            output = io.StringIO()
            RustEmitter(output, collector).emit()
            return output.getvalue()

    def test_different_defaults_keep_distinct_structures(self):
        output = self.generate("""
container authentication { leaf limit { type uint32; default 4096; } }
container authorization { leaf limit { type uint32; default 16384; } }
""")
        self.assertIn("pub struct Authentication", output)
        self.assertIn("pub struct Authorization", output)
        self.assertIn("impl Default for Authentication", output)
        self.assertIn("limit: default_authentication_limit()", output)
        self.assertIn("limit: default_authorization_limit()", output)

    def test_default_initializer_escapes_keyword_field_names(self):
        output = self.generate("""
container settings {
    leaf type { type uint32; default 1; }
    leaf match { type string; }
    leaf-list loop { type string; }
}
""")
        self.assertIn("pub r#type: u32,", output)
        self.assertIn("pub r#match: Option<String>,", output)
        self.assertIn("pub r#loop: Vec<String>,", output)
        self.assertIn("r#type: default_settings_type(),", output)
        self.assertIn("r#match: None,", output)
        self.assertIn("r#loop: Vec::new(),", output)

    def test_required_fields_do_not_get_invented_defaults(self):
        output = self.generate("""
container required { leaf name { type string; mandatory true; } }
container optional { leaf name { type string; } }
""")
        self.assertNotIn("impl Default for Required", output)
        self.assertIn("pub struct Optional", output)
        self.assertEqual(output.count("Serialize, Deserialize, Default)]"), 1)


if __name__ == "__main__":
    unittest.main()