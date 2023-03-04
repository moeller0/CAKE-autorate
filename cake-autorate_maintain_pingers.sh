#!/bin/bash
# TODO
#	make work like before
#	move individual pinger handling into its own files per pinger_type

# Possible performance improvement
#export LC_ALL=C


# FPING FUNCTIONS # 

kill_monitor_reflector_responses_fping()
{
	trap - TERM EXIT

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	# Store baselines and ewmas to files ready for next instance (e.g. after sleep)
	for (( reflector=0; reflector<${no_reflectors}; reflector++ ))
	do
		[[ ! -z ${rtt_baselines_us[${reflectors[reflector]}]} ]] && printf '%s' ${rtt_baselines_us[${reflectors[reflector]}]} > ${run_path}/reflector_${reflectors[reflector]//./-}_baseline_us
		[[ ! -z ${rtt_delta_ewmas_us[${reflectors[reflector]}]} ]] && printf '%s' ${rtt_delta_ewmas_us[${reflectors[reflector]}]} > ${run_path}/reflector_${reflectors[reflector]//./-}_delta_ewma_us
	done

	exit
}

monitor_reflector_responses_fping()
{
	trap '' INT
	trap kill_monitor_reflector_responses_fping TERM EXIT		

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	declare -A rtt_baselines_us
	declare -A rtt_delta_ewmas_us

	t_start_us=${EPOCHREALTIME/./}

	# Read in baselines if they exist, else just set them to 1s (rapidly converges downwards on new RTTs)
	for (( reflector=0; reflector<${no_reflectors}; reflector++ ))
	do
		if [[ -f ${run_path}/reflector_${reflectors[reflector]//./-}_baseline_us ]]; then
			read rtt_baselines_us[${reflectors[reflector]}] < ${run_path}/reflector_${reflectors[reflector]//./-}_baseline_us
		else
			rtt_baselines_us[${reflectors[reflector]}]=100000
		fi
		if [[ -f ${run_path}/reflector_${reflectors[reflector]//./-}_delta_ewma_us ]]; then
			read rtt_delta_ewmas_us[${reflectors[reflector]}] < ${run_path}/reflector_${reflectors[reflector]//./-}_delta_ewma_us
		else
			rtt_delta_ewmas_us[${reflectors[reflector]}]=0
		fi
	done

	output=0

	while true
	do
		while read -t 1 timestamp reflector _ seq_rtt 2>/dev/null
		do 
			t_start_us=${EPOCHREALTIME/./}

			[[ ${seq_rtt} =~ \[([0-9]+)\].*[[:space:]]([0-9]+)\.?([0-9]+)?[[:space:]]ms ]] || continue

			seq=${BASH_REMATCH[1]}

			rtt_us=${BASH_REMATCH[3]}000
			rtt_us=$((${BASH_REMATCH[2]}000+10#${rtt_us:0:3}))

			alpha=$(( (( rtt_us >= rtt_baselines_us[${reflector}] )) ? alpha_baseline_increase : alpha_baseline_decrease ))

			ewma_iteration ${rtt_us} ${alpha} rtt_baselines_us[${reflector}]

			rtt_delta_us=$(( rtt_us-rtt_baselines_us[${reflector}] ))
	
			concurrent_read_integer dl_load_percent ${run_path}/dl_load_percent 
			concurrent_read_integer ul_load_percent ${run_path}/ul_load_percent 

			if(( dl_load_percent < high_load_thr_percent && ul_load_percent < high_load_thr_percent)); then
				ewma_iteration ${rtt_delta_us} ${alpha_delta_ewma} rtt_delta_ewmas_us[${reflector}]
			fi

			dl_owd_baseline_us=$((rtt_baselines_us[${reflector}]/2))
			ul_owd_baseline_us=${dl_owd_baseline_us}

			dl_owd_delta_ewma_us=$((rtt_delta_ewmas_us[${reflector}]/2))
			ul_owd_delta_ewma_us=${dl_owd_delta_ewma_us}

			dl_owd_us=$((rtt_us/2))
			ul_owd_us=${dl_owd_us}

			dl_owd_delta_us=$((rtt_delta_us/2))
			ul_owd_delta_us=${dl_owd_delta_us}
		
			timestamp=${timestamp//[\[\]]}0

			printf '%s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s;\n' "${timestamp}" "${reflector}" "${seq}" "${dl_owd_baseline_us}" "${dl_owd_us}" "${dl_owd_delta_ewma_us}" "${dl_owd_delta_us}" "${ul_owd_baseline_us}" "${ul_owd_us}" "${ul_owd_delta_ewma_us}" "${ul_owd_delta_us}" > ${run_path}/ping_fifo

			#printf -v cur_reflector_stats '%s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s;\n' "${timestamp}" "${reflector}" "${seq}" "${dl_owd_baseline_us}" "${dl_owd_us}" "${dl_owd_delta_ewma_us}" "${dl_owd_delta_us}" "${ul_owd_baseline_us}" "${ul_owd_us}" "${ul_owd_delta_ewma_us}" "${ul_owd_delta_us}"
			#log_msg "REFLECTOR" "${cur_reflector_stats}"


			timestamp_us=${timestamp//[.]}

			printf '%s' "${timestamp_us}" > ${run_path}/reflector_${reflector//./-}_last_timestamp_us
		
			printf '%s' "${dl_owd_baseline_us}" > ${run_path}/reflector_${reflector//./-}_dl_owd_baseline_us
			printf '%s' "${ul_owd_baseline_us}" > ${run_path}/reflector_${reflector//./-}_ul_owd_baseline_us
		
			printf '%s' "${dl_owd_delta_ewma_us}" > ${run_path}/reflector_${reflector//./-}_dl_owd_delta_ewma_us
			printf '%s' "${ul_owd_delta_ewma_us}" > ${run_path}/reflector_${reflector//./-}_ul_owd_delta_ewma_us

			printf '%s' "${timestamp_us}" > ${run_path}/reflectors_last_timestamp_us

		done 2>/dev/null <${run_path}/pinger_${pinger}_fifo
	done
}

# IPUTILS-PING FUNCTIONS

kill_monitor_reflector_responses_ping()
{
	trap - TERM EXIT
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"
	[[ ! -z ${rtt_baseline_us} ]] && printf '%s' ${rtt_baseline_us} > ${run_path}/reflector_${reflectors[pinger]//./-}_baseline_us
	[[ ! -z ${rtt_delta_ewma_us} ]] && printf '%s' ${rtt_delta_ewma_us} > ${run_path}/reflector_${reflectors[pinger]//./-}_delta_ewma_us
	exit
}

monitor_reflector_responses_ping() 
{
	trap '' INT
	trap kill_monitor_reflector_responses_ping TERM EXIT		

	# ping reflector, maintain baseline and output deltas to a common fifo

	local pinger=${1}
	
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	if [[ -f ${run_path}/reflector_${reflectors[pinger]//./-}_baseline_us ]]; then
			read rtt_baseline_us < ${run_path}/reflector_${reflectors[pinger]//./-}_baseline_us
	else
			rtt_baseline_us=100000
	fi

	if [[ -f ${run_path}/reflector_${reflectors[pinger]//./-}_delta_ewma_us ]]; then
			read rtt_delta_ewma_us < ${run_path}/reflector_${reflectors[pinger]//./-}_delta_ewma_us
	else
			rtt_delta_ewma_us=0
	fi

	while true
	do
		while read -t 1 -r timestamp _ _ _ reflector seq_rtt 2>/dev/null
		do
			# If no match then skip onto the next one
			[[ ${seq_rtt} =~ icmp_[s|r]eq=([0-9]+).*time=([0-9]+)\.?([0-9]+)?[[:space:]]ms ]] || continue

			seq=${BASH_REMATCH[1]}

			rtt_us=${BASH_REMATCH[3]}000
			rtt_us=$((${BASH_REMATCH[2]}000+10#${rtt_us:0:3}))

			reflector=${reflector//:/}

			alpha=$(( (( rtt_us >= rtt_baseline_us )) ? alpha_baseline_increase : alpha_baseline_decrease ))

			ewma_iteration ${rtt_us} ${alpha} rtt_baseline_us
		
			rtt_delta_us=$(( rtt_us-rtt_baseline_us ))
	
			concurrent_read_integer dl_load_percent ${run_path}/dl_load_percent
                	concurrent_read_integer ul_load_percent ${run_path}/ul_load_percent

                	if(( dl_load_percent < high_load_thr_percent && ul_load_percent < high_load_thr_percent )); then
				ewma_iteration ${rtt_delta_us} ${alpha_delta_ewma} rtt_delta_ewma_us
			fi

			dl_owd_baseline_us=$((rtt_baseline_us/2))
			ul_owd_baseline_us=${dl_owd_baseline_us}
		
			dl_owd_delta_ewma_us=$((rtt_delta_ewma_us/2))
			ul_owd_delta_ewma_us=${dl_owd_delta_ewma_us}

			dl_owd_us=$((rtt_us/2))
			ul_owd_us=${dl_owd_us}

			dl_owd_delta_us=$((rtt_delta_us/2))
			ul_owd_delta_us=${dl_owd_delta_us}	

			timestamp=${timestamp//[\[\]]}
	
			printf '%s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s;\n' "${timestamp}" "${reflector}" "${seq}" "${dl_owd_baseline_us}" "${dl_owd_us}" "${dl_owd_delta_ewma_us}" "${dl_owd_delta_us}" "${ul_owd_baseline_us}" "${ul_owd_us}" "${ul_owd_delta_ewma_us}" "${ul_owd_delta_us}" > ${run_path}/ping_fifo
		
			timestamp_us=${timestamp//[.]}

			printf '%s' "${timestamp_us}" > ${run_path}/reflector_${reflector//./-}_last_timestamp_us
		
			printf '%s' "${dl_owd_baseline_us}" > ${run_path}/reflector_${reflector//./-}_dl_owd_baseline_us
			printf '%s' "${ul_owd_baseline_us}" > ${run_path}/reflector_${reflector//./-}_ul_owd_baseline_us
		
			printf '%s' "${dl_owd_delta_ewma_us}" > ${run_path}/reflector_${reflector//./-}_dl_owd_delta_ewma_us
			printf '%s' "${ul_owd_delta_ewma_us}" > ${run_path}/reflector_${reflector//./-}_ul_owd_delta_ewma_us

			printf '%s' "${timestamp_us}" > ${run_path}/reflectors_last_timestamp_us

		done 2>/dev/null <${run_path}/pinger_${pinger}_fifo
	done
}

# END OF IPUTILS-PING FUNCTIONS

start_pinger()
{
	local pinger=${1}

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	case ${pinger_binary} in

		fping)
			pinger=0
			mkfifo ${run_path}/pinger_${pinger}_fifo
			exec {pinger_fds[pinger]}<> ${run_path}/pinger_${pinger}_fifo
			log_msg "DEBUG" "${ping_prefix_string} fping ${ping_extra_args} --timestamp --loop --period ${reflector_ping_interval_ms} --interval ${ping_response_interval_ms} --timeout 10000 ${reflectors[@]:0:${no_pingers}} 2> /dev/null > ${run_path}/pinger_${pinger}_fifo&"
			${ping_prefix_string} fping ${ping_extra_args} --timestamp --loop --period ${reflector_ping_interval_ms} --interval ${ping_response_interval_ms} --timeout 10000 ${reflectors[@]:0:${no_pingers}} 2> /dev/null > ${run_path}/pinger_${pinger}_fifo&
		;;
		ping)
			mkfifo ${run_path}/pinger_${pinger}_fifo
			exec {pinger_fds[pinger]}<> ${run_path}/pinger_${pinger}_fifo
			sleep_until_next_pinger_time_slot ${pinger}
			${ping_prefix_string} ping ${ping_extra_args} -D -i ${reflector_ping_interval_s} ${reflectors[pinger]} 2> /dev/null > ${run_path}/pinger_${pinger}_fifo &
		;;
	esac
	
	pinger_pids[pinger]=${!}
	log_msg "DEBUG" "Started pinger ${pinger} with PID: ${pinger_pids[pinger]}"
	log_process_cmdline pinger_pids[pinger]

	monitor_reflector_responses_${pinger_binary} ${pinger} &
	monitor_pids[pinger]=${!}
	log_process_cmdline monitor_pids[pinger]
}

start_pingers()
{
	# Initiate pingers
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	case ${pinger_binary} in

		fping)
			start_pinger 0
		;;
		ping)
			for ((pinger=0; pinger<${no_pingers}; pinger++))
			do
				start_pinger ${pinger}
			done
		;;
	esac
}


kill_pinger()
{
	local pinger=${1}
	
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	case ${pinger_binary} in

		fping)
			pinger=0
		;;
		*)
			:
		;;
	esac

	kill_and_wait_by_pid_name pinger_pids[pinger] ${err_silence}

	kill_and_wait_by_pid_name monitor_pids[pinger] 0

	exec {pinger_fds[pinger]}<&-
	[[ -p ${run_path}/pinger_${pinger}_fifo ]] && rm ${run_path}/pinger_${pinger}_fifo
}

kill_pingers()
{
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	case ${pinger_binary} in

		fping)
			log_msg "DEBUG" "Killing fping instance."
			kill_pinger 0
		;;
		ping)
			for (( pinger=0; pinger<${no_pingers}; pinger++))
			do
				log_msg "DEBUG" "Killing pinger instance: ${pinger}"
				kill_pinger ${pinger}
			done
		;;
	esac
}

replace_pinger_reflector()
{
	# pingers always use reflectors[0]..[no_pingers-1] as the initial set
	# and the additional reflectors are spare reflectors should any from initial set go stale
	# a bad reflector in the initial set is replaced with ${reflectors[no_pingers]}
	# ${reflectors[no_pingers]} is then unset
	# and the the bad reflector moved to the back of the queue (last element in ${reflectors[]})
	# and finally the indices for ${reflectors} are updated to reflect the new order
	
	local pinger=${1}
	
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	if (( ${no_reflectors} > ${no_pingers} )); then
		log_msg "DEBUG" "replacing reflector: ${reflectors[pinger]} with ${reflectors[no_pingers]}."
		kill_pinger ${pinger}
		bad_reflector=${reflectors[pinger]}
		# overwrite the bad reflector with the reflector that is next in the queue (the one after 0..${no_pingers}-1)
		reflectors[pinger]=${reflectors[no_pingers]}
		# remove the new reflector from the list of additional reflectors beginning from ${reflectors[no_pingers]}
		unset reflectors[no_pingers]
		# bad reflector goes to the back of the queue
		reflectors+=(${bad_reflector})
		# reset array indices
		reflectors=(${reflectors[*]})
		# set up the new pinger with the new reflector and retain pid	
		start_pinger ${pinger}
	else
		log_msg "DEBUG" "No additional reflectors specified so just retaining: ${reflectors[pinger]}."
		reflector_offences[pinger]=0
	fi

}


kill_maintain_pingers()
{
	trap - TERM EXIT

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	log_msg "DEBUG" "Terminating maintain_pingers."

	kill_pingers

	exit
}

pause_reflector_maintenance()
{
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	if ((reflector_maintenance_paused==0)); then
		log_msg "DEBUG" "Pausing reflector health check (SIGUSR1)."
		reflector_maintenance_paused=1
	else
		log_msg "DEBUG" "Resuming reflector health check (SIGUSR1)."
		reflector_maintenance_paused=0
	fi
}

pause_maintain_pingers()
{
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	if ((maintain_pingers_paused==0)); then
		log_msg "DEBUG" "Pausing maintain pingers (SIGUSR2)."
		kill_pingers		
		maintain_pingers_paused=1
	else
		log_msg "DEBUG" "Resuming maintain pingers (SIGUSR2)."
		start_pingers
		maintain_pingers_paused=0
	fi
}



# used to be a function
#maintain_pingers()
#{
cur_config_file=${1}
# this is a bit too much, but to get started this should do
. ${cur_config_file}


# get the directory where this script (and its helps reside)
# and source autorate_functions.sh
cur_filename="$( readlink -f -- "${0}" )"
autorate_code_dir="$( dirname -- "${cur_filename}" )"
. ${autorate_code_dir}/cake-autorate_common_functions.sh
log_msg "DEBUG" "maintain_pingers: autorate_code_dir: ${autorate_code_dir}"


# Convert human readable parameters to values that work with integer arithmetic
#printf -v dl_delay_thr_us %.0f "${dl_delay_thr_ms}e3"
#printf -v ul_delay_thr_us %.0f "${ul_delay_thr_ms}e3"
printf -v alpha_baseline_increase %.0f "${alpha_baseline_increase}e6"
printf -v alpha_baseline_decrease %.0f "${alpha_baseline_decrease}e6"   
printf -v alpha_delta_ewma %.0f "${alpha_delta_ewma}e6"   
#printf -v achieved_rate_adjust_down_bufferbloat %.0f "${achieved_rate_adjust_down_bufferbloat}e3"
#printf -v shaper_rate_adjust_down_bufferbloat %.0f "${shaper_rate_adjust_down_bufferbloat}e3"
#printf -v shaper_rate_adjust_up_load_high %.0f "${shaper_rate_adjust_up_load_high}e3"
#printf -v shaper_rate_adjust_down_load_low %.0f "${shaper_rate_adjust_down_load_low}e3"
#printf -v shaper_rate_adjust_up_load_low %.0f "${shaper_rate_adjust_up_load_low}e3"
printf -v high_load_thr_percent %.0f "${high_load_thr}e2"
printf -v reflector_ping_interval_ms %.0f "${reflector_ping_interval_s}e3"
printf -v reflector_ping_interval_us %.0f "${reflector_ping_interval_s}e6"
#printf -v monitor_achieved_rates_interval_us %.0f "${monitor_achieved_rates_interval_ms}e3"
#printf -v sustained_idle_sleep_thr_us %.0f "${sustained_idle_sleep_thr_s}e6"
printf -v reflector_response_deadline_us %.0f "${reflector_response_deadline_s}e6"
printf -v reflector_owd_baseline_delta_thr_us %.0f "${reflector_owd_baseline_delta_thr_ms}e3"
printf -v reflector_owd_delta_ewma_delta_thr_us %.0f "${reflector_owd_delta_ewma_delta_thr_ms}e3"
#printf -v startup_wait_us %.0f "${startup_wait_s}e6"
#printf -v global_ping_response_timeout_us %.0f "${global_ping_response_timeout_s}e6"
#printf -v bufferbloat_refractory_period_us %.0f "${bufferbloat_refractory_period_ms}e3"
#printf -v decay_refractory_period_us %.0f "${decay_refractory_period_ms}e3"

#for (( i=0; i<${#sss_times_s[@]}; i++ ));
#do
#	printf -v sss_times_us[i] %.0f\\n "${sss_times_s[i]}e6"
#done
#printf -v sss_compensation_pre_duration_us %.0f "${sss_compensation_pre_duration_ms}e3"
#printf -v sss_compensation_post_duration_us %.0f "${sss_compensation_post_duration_ms}e3"

# these are also exported from main, maybe do not recalculate them here again?
ping_response_interval_us=$(( reflector_ping_interval_us / no_pingers ))
ping_response_interval_ms=$(( ping_response_interval_us / 1000 ))

concurrent_read_integer_interval_us=$((ping_response_interval_us/4)) 

no_reflectors=${#reflectors[@]} 

	# this is the place where pingers and their monitors get created and torn down
	# this state machine needs to assert, that killing/starting is properly serialized 
	# 
	# TODO:
	#	convert to state machine and orchestrate all starting/killing from inside the state machine
	#	move to external file so the bash process gets an interpretable name in ps output (move all dual use functions into sourced "library")
	#		pass parameters explicitly as arguments instead of inheriting the environment...
	#	simplify function?
	#	make sure called functions are resistent to INT/TERM/EXIT
	#	maybe use US1/USR2 in combination with a bidirectional FIFO to exchange information...
	#		use USR1/USR2 as use USR1 to request a command read from the partner, and wait 
	#			the partner to t=return USR2 to signal success, or similar
	#		like the set of used reflectors and more potential state changes
	#	write out reflector set on re-sorting events...
	#	
	
	# this initiates the pingers and monitors reflector health, rotating reflectors as necessary

 	trap '' INT

	# use these to toogle state, bot to branch out into different function...	
	trap 'terminate_reflector_maintenance=1' TERM EXIT

	# call these functions from inside the state machine?
	trap 'pause_reflector_maintenance' USR1
	trap 'pause_maintain_pingers' USR2

cur_script_name="$( basename -- ${0} )"
#log_msg "DEBUG" "Starting: cake-autorate_maintain_pingers (0: ${0})) with PID: ${BASHPID}"
log_msg "DEBUG" "Starting: ${cur_script_name} with PID: ${BASHPID}"

#	# local helper to keep the state machine neat and tidy
#	declare -A state_array 
#	state_array[last_state_change_ts]=${EPOCHREALTIME/./}	# timestamp the state was entered
#	state_array[old_state]="NONE"							# the previous state
#	state_array[new_state]="INITIALIZE"						# the new state, if old == new, state was not changed
#	state_array[in_state_cycles]=0							# number of consecuitive cycles without state change, if 1 state was just entered, use to nitialize things
#	next_state="INITIALIZE"



	declare -A dl_owd_baselines_us
	declare -A ul_owd_baselines_us
	declare -A dl_owd_delta_ewmas_us
	declare -A ul_owd_delta_ewmas_us

	err_silence=0
	
	terminate_reflector_maintenance=0

	reflector_maintenance_paused=0
	maintain_pingers_paused=0

	reflector_offences_idx=0

	pingers_t_start_us=${EPOCHREALTIME/./}	
	t_last_reflector_replacement_us=${EPOCHREALTIME/./}	
	t_last_reflector_comparison_us=${EPOCHREALTIME/./}	


	# load per reflector information
	for (( reflector=0; reflector<${no_reflectors}; reflector++ ))
	do
		printf '%s' "${pingers_t_start_us}" > ${run_path}/reflector_${reflectors[reflector]//./-}_last_timestamp_us
	done
	
	printf '%s' "${pingers_t_start_us}" > ${run_path}/reflectors_last_timestamp_us

        # For each pinger initialize record of offences
        for ((pinger=0; pinger<${no_pingers}; pinger++))                           
	do
		declare -n reflector_offences="reflector_${pinger}_offences"                                                                                                               
		for ((i=0; i<${reflector_misbehaving_detection_window}; i++)) do reflector_offences[i]=0; done
                sum_reflector_offences[pinger]=0
        done

	start_pingers
	

	# Reflector maintenance loop - verifies reflectors have not gone stale and rotates reflectors as necessary
	while ((terminate_reflector_maintenance == 0))
	do
		sleep_s ${reflector_health_check_interval_s}

		((reflector_maintenance_paused || maintain_pingers_paused)) && continue

		if(( ${EPOCHREALTIME/./}>(t_last_reflector_replacement_us+reflector_replacement_interval_mins*60*1000000))); then
	
			log_msg "DEBUG" "reflector: ${reflectors[pinger]} randomly selected for replacement."
			replace_pinger_reflector $((RANDOM%no_pingers))
			t_last_reflector_replacement_us=${EPOCHREALTIME/./}	
			continue
		fi

		if(( ${EPOCHREALTIME/./}>(t_last_reflector_comparison_us+reflector_comparison_interval_mins*60*1000000) )); then

			t_last_reflector_comparison_us=${EPOCHREALTIME/./}	
			
			concurrent_read_integer dl_min_owd_baseline_us ${run_path}/reflector_${reflectors[0]//./-}_dl_owd_baseline_us
			(( ${?} != 0 )) && continue
			concurrent_read_integer dl_min_owd_delta_ewma_us ${run_path}/reflector_${reflectors[0]//./-}_dl_owd_delta_ewma_us
			(( ${?} != 0 )) && continue
			concurrent_read_integer ul_min_owd_baseline_us ${run_path}/reflector_${reflectors[0]//./-}_ul_owd_baseline_us
			(( ${?} != 0 )) && continue
			concurrent_read_integer ul_min_owd_delta_ewma_us ${run_path}/reflector_${reflectors[0]//./-}_ul_owd_delta_ewma_us
			(( ${?} != 0 )) && continue
			
			concurrent_read_integer compensated_dl_delay_thr_us ${run_path}/compensated_dl_delay_thr_us
			concurrent_read_integer compensated_ul_delay_thr_us ${run_path}/compensated_ul_delay_thr_us

			for ((pinger=0; pinger<${no_pingers}; pinger++))
			do
				concurrent_read_integer dl_owd_baselines_us[${reflectors[pinger]}] ${run_path}/reflector_${reflectors[pinger]//./-}_dl_owd_baseline_us
				(( ${?} != 0 )) && continue 2
				concurrent_read_integer dl_owd_delta_ewmas_us[${reflectors[pinger]}] ${run_path}/reflector_${reflectors[pinger]//./-}_dl_owd_delta_ewma_us
				(( ${?} != 0 )) && continue 2
				concurrent_read_integer ul_owd_baselines_us[${reflectors[pinger]}] ${run_path}/reflector_${reflectors[pinger]//./-}_ul_owd_baseline_us
				(( ${?} != 0 )) && continue 2
				concurrent_read_integer ul_owd_delta_ewmas_us[${reflectors[pinger]}] ${run_path}/reflector_${reflectors[pinger]//./-}_ul_owd_delta_ewma_us
				(( ${?} != 0 )) && continue 2
				
				((   dl_owd_baselines_us[${reflectors[pinger]}] < dl_min_owd_baseline_us   )) && dl_min_owd_baseline_us=${dl_owd_baselines_us[${reflectors[pinger]}]}
				(( dl_owd_delta_ewmas_us[${reflectors[pinger]}] < dl_min_owd_delta_ewma_us )) && dl_min_owd_delta_ewma_us=${dl_owd_delta_ewmas_us[${reflectors[pinger]}]}
				((   ul_owd_baselines_us[${reflectors[pinger]}] < ul_min_owd_baseline_us   )) && ul_min_owd_baseline_us=${ul_owd_baselines_us[${reflectors[pinger]}]}
				(( ul_owd_delta_ewmas_us[${reflectors[pinger]}] < ul_min_owd_delta_ewma_us )) && ul_min_owd_delta_ewma_us=${ul_owd_delta_ewmas_us[${reflectors[pinger]}]}
			done

			for ((pinger=0; pinger<${no_pingers}; pinger++))
			do
				
				dl_owd_baseline_delta_us=$((   dl_owd_baselines_us[${reflectors[pinger]}]   - dl_min_owd_baseline_us   ))
				dl_owd_delta_ewma_delta_us=$(( dl_owd_delta_ewmas_us[${reflectors[pinger]}] - dl_min_owd_delta_ewma_us ))
				ul_owd_baseline_delta_us=$((   ul_owd_baselines_us[${reflectors[pinger]}]   - ul_min_owd_baseline_us   ))
				ul_owd_delta_ewma_delta_us=$(( ul_owd_delta_ewmas_us[${reflectors[pinger]}] - ul_min_owd_delta_ewma_us ))

				if ((${output_reflector_stats})); then
					printf -v reflector_stats '%s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s' ${EPOCHREALTIME} ${reflectors[pinger]} ${dl_min_owd_baseline_us} ${dl_owd_baselines_us[${reflectors[pinger]}]} ${dl_owd_baseline_delta_us} ${reflector_owd_baseline_delta_thr_us} ${dl_min_owd_delta_ewma_us} ${dl_owd_delta_ewmas_us[${reflectors[pinger]}]} ${dl_owd_delta_ewma_delta_us} ${reflector_owd_delta_ewma_delta_thr_us} ${ul_min_owd_baseline_us} ${ul_owd_baselines_us[${reflectors[pinger]}]} ${ul_owd_baseline_delta_us} ${reflector_owd_baseline_delta_thr_us} ${ul_min_owd_delta_ewma_us} ${ul_owd_delta_ewmas_us[${reflectors[pinger]}]} ${ul_owd_delta_ewma_delta_us} ${reflector_owd_delta_ewma_delta_thr_us}
					log_msg "REFLECTOR" "${reflector_stats}"
				fi

				if (( dl_owd_baseline_delta_us > reflector_owd_baseline_delta_thr_us )); then
					log_msg "DEBUG" "Warning: reflector: ${reflectors[pinger]} dl_owd_baseline_us exceeds the minimum by set threshold."
					replace_pinger_reflector ${pinger}
					continue 2
				fi

				if (( dl_owd_delta_ewma_delta_us > reflector_owd_delta_ewma_delta_thr_us )); then
					log_msg "DEBUG" "Warning: reflector: ${reflectors[pinger]} dl_owd_delta_ewma_us exceeds the minimum by set threshold."
					replace_pinger_reflector ${pinger}
					continue 2
				fi
				
				if (( ul_owd_baseline_delta_us > reflector_owd_baseline_delta_thr_us )); then
					log_msg "DEBUG" "Warning: reflector: ${reflectors[pinger]} ul_owd_baseline_us exceeds the minimum by set threshold."
					replace_pinger_reflector ${pinger}
					continue 2
				fi

				if (( ul_owd_delta_ewma_delta_us > reflector_owd_delta_ewma_delta_thr_us )); then
					log_msg "DEBUG" "Warning: reflector: ${reflectors[pinger]} ul_owd_delta_ewma_us exceeds the minimum by set threshold."
					replace_pinger_reflector ${pinger}
					continue 2
				fi
			done

		fi

		enable_replace_pinger_reflector=1

		for ((pinger=0; pinger<${no_pingers}; pinger++))
		do
			reflector_check_time_us=${EPOCHREALTIME/./}
			concurrent_read_integer reflector_last_timestamp_us ${run_path}/reflector_${reflectors[pinger]//./-}_last_timestamp_us
			declare -n reflector_offences="reflector_${pinger}_offences"

			(( reflector_offences[reflector_offences_idx] )) && ((sum_reflector_offences[pinger]--))
			reflector_offences[reflector_offences_idx]=$(( (((${EPOCHREALTIME/./}-reflector_last_timestamp_us) > reflector_response_deadline_us)) ? 1 : 0 ))
			
			if (( reflector_offences[reflector_offences_idx] )); then 
				((sum_reflector_offences[pinger]++))
				log_msg "DEBUG" "no ping response from reflector: ${reflectors[pinger]} within reflector_response_deadline: ${reflector_response_deadline_s}s"
				log_msg "DEBUG" "reflector=${reflectors[pinger]}, sum_reflector_offences=${sum_reflector_offences[pinger]} and reflector_misbehaving_detection_thr=${reflector_misbehaving_detection_thr}"
			fi

			if (( sum_reflector_offences[pinger] >= reflector_misbehaving_detection_thr )); then

				log_msg "DEBUG" "Warning: reflector: ${reflectors[pinger]} seems to be misbehaving."
				if ((enable_replace_pinger_reflector)); then
					replace_pinger_reflector ${pinger}
					for ((i=0; i<reflector_misbehaving_detection_window; i++)) do reflector_offences[i]=0; done
					sum_reflector_offences[pinger]=0
					enable_replace_pinger_reflector=0
				else
					log_msg "DEBUG" "Warning: skipping replacement of reflector: ${reflectors[pinger]} given prior replacement within this reflector health check cycle."
				fi
			fi		
		done
		((reflector_offences_idx=(reflector_offences_idx+1)%reflector_misbehaving_detection_window))
	done

	kill_maintain_pingers
#}
