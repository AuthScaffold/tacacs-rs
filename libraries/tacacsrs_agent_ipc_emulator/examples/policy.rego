# OPA/Rego policy for the TACACS+ agent IPC emulator.
#
# Each captured IPC request is supplied as Rego `input`. The emulator evaluates
# `data.tacacs.emulator.decision` and uses the returned object as the response.
#
# `input` always contains an `rpc` discriminator ("Accounting" or
# "Authorization") plus the captured request fields (user, port,
# remote_address, command, command_arguments, and for authorization
# privilege_level and args).
#
# A `decision` is an object with a `type` of "response" or "error":
#   response: {server, status, server_message, data, args, delay_ms?}
#   error:    {message, server, retriable, delay_ms?}
#
# When `decision` is left undefined the emulator returns a gRPC NotFound for
# Accounting and a Fail response for Authorization.
package tacacs.emulator

import rego.v1

server := "tacacs-primary:49"

# ------------------------------- Accounting -------------------------------

# Record accounting for the admin "show" command, with an artificial delay.
decision := {
"type": "response",
"server": server,
"status": "Success",
"server_message": "",
"data": "",
"delay_ms": 50,
} if {
input.rpc == "Accounting"
input.user == "admin"
input.command == "show"
}

# Any other accounting request is reported as a retriable service error.
decision := {
"type": "error",
"message": "No responsive TACACS+ servers are currently available",
"server": "",
"retriable": true,
} if {
input.rpc == "Accounting"
not accounting_recorded
}

accounting_recorded if {
input.user == "admin"
input.command == "show"
}

# ------------------------------ Authorization -----------------------------

# Deny a command when one of its arguments is on the per-command denylist
# defined in the fixed policy data document.
decision := {
"type": "response",
"server": server,
"status": "Fail",
"server_message": sprintf("argument %v is not permitted for %v", [denied_argument, input.command]),
"data": "",
"args": [],
} if {
input.rpc == "Authorization"
denied_argument != ""
}

# Otherwise authorize the command.
decision := {
"type": "response",
"server": server,
"status": "PassAdd",
"server_message": "",
"data": "",
"args": [],
} if {
input.rpc == "Authorization"
denied_argument == ""
}

# The first denied argument present in the request, or "" when none apply.
denied_argument := arg if {
some arg in data.denied[input.command]
arg in input.command_arguments
} else := ""
