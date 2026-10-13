"""Check generated defaults and structural reuse for policy containers."""

import io
import tempfile
import unittest

from pyang import context, repository
from plugins.yang2rust import Collector, RustEmitter


class GeneratedDefaultsTests(unittest.TestCase):
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