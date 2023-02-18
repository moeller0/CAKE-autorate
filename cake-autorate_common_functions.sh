################################################################################
#
# Helper functions for cake-autorate
#	should be sourced by all scripts that want to use these functions
#
################################################################################


# not intended to be called just for documentation purposes
get_current_time_us()
{
    local -n return_ts=${1}
    
    # just remove the '.' EPOCHREALTIME is already in us
    return_ts=${EPOCHREALTIME/./}
}


