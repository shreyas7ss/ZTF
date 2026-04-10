package soc.authz

import rego.v1

# Default deny all
default allow = false

# Allow only if:
# 1. The requested tool is in the agent's permitted tools list
# 2. The agent is not in the quarantined list
allow if {
    some i
    input.tool == input.permitted_tools[i]
    not is_quarantined
}

# Check if the agent ID exists in the data.quarantined_agents list
is_quarantined if {
    input.agent_id == data.quarantined_agents[_]
}
