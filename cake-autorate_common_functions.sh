################################################################################
#
# Helper functions for cake-autorate
#	should be sourced by all scripts that want to use these functions
#
################################################################################

# this is from cake-autorate.sh
log_msg()
{
	# send logging message to terminal, log file fifo, log file and/or system logger

	local type=${1}
	local msg=${2}

	case ${type} in

		DEBUG)
			[[ "${debug}" == "0" ]] && return # skip over DEBUG messages where debug disabled 
			log_timestamp=${EPOCHREALTIME}
			((log_DEBUG_messages_to_syslog)) && ((use_logger)) && logger -t "cake-autorate.${instance_id}" "${type}: ${log_timestamp} ${msg}"
			;;
	
        	ERROR)
			log_timestamp=${EPOCHREALTIME}
			((use_logger)) && logger -t "cake-autorate.${instance_id}" "${type}: ${log_timestamp} ${msg}"
			;;

        	SYSLOG)
			log_timestamp=${EPOCHREALTIME}
			((use_logger)) && logger -t "cake-autorate.${instance_id}" "INFO: ${log_timestamp} ${msg}"
			;;
		*)
			log_timestamp=${EPOCHREALTIME}
			;;
	esac
			
	# Output to the log file fifo if available (for rotation handling)
	# else output directly to the log file
	if [[ -p ${run_path}/log_fifo ]]; then
		((log_to_file)) && printf '%s; %(%F-%H:%M:%S)T; %s; %s\n' "${type}" -1 "${log_timestamp}" "${msg}" > ${run_path}/log_fifo
	else
       		((log_to_file)) && printf '%s; %(%F-%H:%M:%S)T; %s; %s\n' "${type}" -1 "${log_timestamp}" "${msg}" >> ${log_file_path}
	fi
        
	((terminal)) && printf '%s; %(%F-%H:%M:%S)T; %s; %s\n' "${type}" -1 "${log_timestamp}" "${msg}"
}

log_process_cmdline()
{
	local -n process_pid=${1}

	for ((read_try=0; read_try<10; read_try++))
	do
		read -r process_cmdline < <( tr '\0' ' ' < /proc/${process_pid}/cmdline )
		[[ -z ${process_cmdline} ]] || break
		sleep_s 0.01
	done
	log_msg "DEBUG" "${!process_pid}=${process_pid} cmdline: ${process_cmdline}"
}

concurrent_read_integer()
{
	# in the context of a single process that writes to a file and
	# a separate process that reads from the file, costly calls to 
	# the external flock binary can be avoided for the reason that
	# the read either reads in a blank value or the last true value
	# and so it is possible to just read, test and reread if necessary

	local -n value=${1}
 	local path=${2}

	for ((read_try=1; read_try<11; read_try++))
	do
		read -r value < ${path};

		# Verify value is a positive or negative integer 
		# 1st capture group (optional): negative sign
		# 2nd capture group (optional): leading zeros
		# 3rd capture group (not optional): numeric sequence 
		if [[ ${value} =~ ^([-])?([0]+)?([0-9]+)$ ]]; then

			# Strip out any leading zeros and employ arithmetic context
			value=$(( ${BASH_REMATCH[1]}BASH_REMATCH[3] ))
			true
			return

		else
			if ((${debug})); then
				read -r caller_output< <(caller)
				log_msg "DEBUG" "concurrent_read_integer() misfire: ${read_try} of 10, with the following particulars:"
				log_msg "DEBUG" "caller=${caller_output}, value=${value} and path=${path}"
			fi 
			sleep_us ${concurrent_read_integer_interval_us}
			continue
		fi
	done
	
	if ((${debug})); then
		read -r caller_output< <(caller)
		log_msg "ERROR" "If you see this, then please report these messages (ideally with log file)" 
		log_msg "ERROR" "at the cake-autorate forum of OpenWrt and/or at github.com/lynxthecat/cake-autorate"
		log_msg "ERROR" "concurrent_read_integer() 10x misfires, with the following particulars:"
		log_msg "ERROR" "caller=${caller_output}, value=${value} and path=${path}"
	fi 
	value=0
	false
	return
}



debug_cmd()
{
	# Usage: debug_cmd debug_msg err_silence cmd arg1 arg2, etc.

	# Error messages are output as log_msg ERROR messages
	# Or set error_silence=1 to output errors as log_msg DEBUG messages

	local debug_msg=${1}
	local err_silence=${2}
        local cmd=${3}

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	shift 3

	local args=$@
        
	local caller_id
        local err_type

        local ret
        local stderr

        err_type="ERROR"

        if ((err_silence)); then
                err_type="DEBUG"
        fi

	stderr=$(${cmd} ${args} 2>&1)
        ret=${?}
	
	caller_id=$(caller)

	if ((ret==0)); then
                log_msg "DEBUG" "debug_cmd: err_silence=${err_silence}; debug_msg=${debug_msg}; caller_id=${caller_id}; command=${cmd} ${args}; result=SUCCESS"
        else
		[[ "${err_type}" == "DEBUG" && "${debug}" == "0" ]] && continue # if debug disabled, then skip on DEBUG but not on ERROR

           	log_msg "${err_type}" "debug_cmd: err_silence=${err_silence}; debug_msg=${debug_msg}; caller_id=${caller_id}; command=${cmd} ${args}; result=FAILURE (${ret})"
               	log_msg "${err_type}" "debug_cmd: LAST ERROR (${stderr})"
		frame=1
		caller_output=$(caller ${frame})
		while ((${?}==0))
		do
           		log_msg "${err_type}" "debug_cmd: CALL CHAIN: ${caller_output}"
			((++frame))
			caller_output=$(caller ${frame})
		done
        fi
}


kill_and_wait_by_pid_name()
{
	local -n pid=${1}
	local err_silence=${2}
	
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	if ! [[ -z ${pid} ]]; then
		if [[ -d "/proc/${pid}" ]]; then
			log_process_cmdline pid
	    		debug_cmd ${!pid} ${err_silence} kill ${pid}
			wait ${pid}
	    	else
			log_msg "DEBUG" "expected ${!pid} process: ${pid} does not exist - nothing to kill." 
	    	fi
	else
		log_msg "DEBUG" "pid (${!pid}) is empty, nothing to kill." 	        
	fi

	# Reset pid
	pid=

}

sleep_remaining_tick_time()
{
	# sleeps until the end of the tick duration

	local t_start_us=${1} # (microseconds)
	local tick_duration_us=${2} # (microseconds)

	sleep_duration_us=$(( ${t_start_us} + ${tick_duration_us} - ${EPOCHREALTIME/./} ))
	
        if (( ${sleep_duration_us} > 0 )); then
		sleep_us ${sleep_duration_us}
	fi
}

sleep_until_next_pinger_time_slot()
{
	# wait until next pinger time slot and start pinger in its slot
	# this allows pingers to be stopped and started (e.g. during sleep or reflector rotation)
	# whilst ensuring pings will remain spaced out appropriately to maintain granularity

	local pinger=${1}
	
	t_start_us=${EPOCHREALTIME/./}
	time_to_next_time_slot_us=$(( (reflector_ping_interval_us-(t_start_us-pingers_t_start_us)%reflector_ping_interval_us) + pinger*ping_response_interval_us ))
	sleep_remaining_tick_time ${t_start_us} ${time_to_next_time_slot_us}
}

sleep_s()
{
	# calling external sleep binary is slow
	# bash does have a loadable sleep 
	# but read's timeout can more portably be exploited and this is apparently even faster anyway

	local sleep_duration_s=${1} # (seconds, e.g. 0.5, 1 or 1.5)

	read -t ${sleep_duration_s} < ${run_path}/sleep_fifo
}

sleep_us()
{
	# calling external sleep binary is slow
	# bash does have a loadable sleep 
	# but read's timeout can more portably be exploited and this is apparently even faster anyway

	local sleep_duration_us=${1} # (microseconds)
	
	sleep_duration_s=000000${sleep_duration_us}
	sleep_duration_s=$((10#${sleep_duration_s::-6})).${sleep_duration_s: -6}
	read -t ${sleep_duration_s} < ${run_path}/sleep_fifo
}

# not intended to be called just for documentation purposes
get_current_time_us()
{
    local -n return_ts=${1}
    
    # just remove the '.' EPOCHREALTIME is already in us
    return_ts=${EPOCHREALTIME/./}
}

# collect some housekeeping useful for fall-through state machines
update_state_data()                                                                                                                                                                                                                         
{                                                                                                                                                                                                                                           
	# this reads in the state array and updates it and return is
	local new_state=${1}                                                                                                                                                                                                                
	local -n updated_state_array=${2}

#	echo "new_state: ${new_state}"
#	echo "updated_state_array pre-update: ${updated_state_array[*]}"

	# just do this unconditionally as this needs doing anyway
	updated_state_array[old_state]="${updated_state_array[current_state]}"



	if [ "${new_state}" != "${updated_state_array[new_state]}" ]; then
	    # state change update
	    updated_state_array[last_state_change_ts]=${EPOCHREALTIME/./}
	    updated_state_array[new_state]=${new_state}
	    updated_state_array[in_state_cycles]=1
	else
	    # skip the next assignment as the values do not change
	    #updated_state_array[new_state]=${new_state}
	    (( updated_state_array[in_state_cycles]++ ))
	fi
#	echo "updated_state_array post-update: ${updated_state_array[*]}"
	return 0
}        


fn_test_state_update()
{
    declare -A state_array 
    state_array[last_state_change_ts]=${EPOCHREALTIME/./}	# timestamp the state was entered
    state_array[old_state]="last_state"						# the previous state
    state_array[new_state]="current_state"					# the new state, if old == new, state was not changed
    state_array[in_state_cycles]=0							# number of consecuitive cycles without state change, if 1 state was just entered, use to nitialize things

    echo "main: state_array: ${state_array[*]}"

    update_state_data "new" state_array
    echo "main: updated state_array: ${state_array[*]}"
    
    update_state_data "new" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new2" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new2" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new" state_array
    echo "main: updated state_array: ${state_array[*]}"

    update_state_data "new2" state_array
    echo "main: updated state_array: ${state_array[*]}"
}
#fn_test_state_update
