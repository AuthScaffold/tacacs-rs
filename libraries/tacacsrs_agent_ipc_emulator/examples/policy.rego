# OPA/Rego policy for the TACACS+ agent IPC emulator.
#
# Rego receives each captured IPC request as `input`. The emulator evaluates
# `data.tacacs.emulator.decision`. It uses the returned object as the response.
#
# `input` contains an `rpc` discriminator with a value of "Accounting" or
# "Authorization". It also contains the captured request fields. Authorization
# input includes privilege_level and args.
#
# A `decision` object has a `type` of "response" or "error":
#   response: {server, status, server_message, data, args, delay_ms?}
#   error:    {message, server, retriable, delay_ms?}
#
# If `decision` is undefined, the emulator returns a gRPC NotFound error for
# Accounting. It returns a Fail response for Authorization.
package tacacs.emulator

import rego.v1

server := "tacacs-primary:49"

# ------------------------------- Accounting -------------------------------

# This rule records the admin "show" command after an artificial delay.
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

# The emulator returns a retriable service error for all other accounting requests.
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

# This rule denies a command if an argument is in the deny list for that command.
# The fixed policy data document defines the deny list.
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

# The emulator authorizes all other commands.
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

# This value is the first denied argument in the request.
# The value is "" if no argument is denied.
denied_argument := arg if {
some arg in data.denied[input.command]
arg in input.command_arguments
} else := ""
