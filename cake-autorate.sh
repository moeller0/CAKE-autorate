#!/bin/bash

# CAKE-autorate automatically adjusts CAKE bandwidth(s)
# in dependence on: a) receive and transmit transfer rates; and b) latency
# (or can just be used to monitor and log transfer rates and latency)

# requires packages: bash; and one of the supported ping binaries

# each cake-autorate instance must be configured using a corresponding config file 

# Project homepage: https://github.com/lynxthecat/cake-autorate
# Licence details:  https://github.com/lynxthecat/cake-autorate/blob/main/LICENCE.md

# Author: @Lynx (OpenWrt forum)
# Inspiration taken from: @moeller0 (OpenWrt forum)

# Possible performance improvement
export LC_ALL=C

trap cleanup_and_killall INT TERM EXIT


cleanup_and_killall()
{	
	trap - INT TERM EXIT
	
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"
	
	log_msg "INFO" "Stopping cake-autorate with PID: ${BASHPID} and config: ${config_path}"
	
	log_msg "INFO" ""
	log_msg "INFO" "Killing all background processes and cleaning up temporary files."

	if ! [[ -z ${maintain_pingers_pid} ]]; then
		log_msg "DEBUG" "Terminating maintain_pingers_pid: ${maintain_pingers_pid}."
		kill_and_wait_by_pid_name maintain_pingers_pid 0
	fi

	if ! [[ -z ${monitor_achieved_rates_pid} ]]; then
		log_msg "DEBUG" "Terminating monitor_achieved_rates_pid: ${monitor_achieved_rates_pid}."
		kill_and_wait_by_pid_name monitor_achieved_rates_pid 0
	fi

	if ! [[ -z ${maintain_log_file_pid} ]]; then
		log_msg "DEBUG" "Terminating maintain_log_file_pid: ${maintain_log_file_pid}."
		kill_and_wait_by_pid_name maintain_log_file_pid 0
	fi

	[[ -d ${run_path} ]] && rm -r ${run_path}
	[[ -d /var/run/cake-autorate ]] && compgen -G /var/run/cake-autorate/* > /dev/null || rm -r /var/run/cake-autorate

	log_msg "SYSLOG" "Stopped cake-autorate with PID: ${BASHPID} and config: ${config_path}"
	exit
}


print_headers()
{
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	header="DATA_HEADER; LOG_DATETIME; LOG_TIMESTAMP; PROC_TIME_US; DL_ACHIEVED_RATE_KBPS; UL_ACHIEVED_RATE_KBPS; DL_LOAD_PERCENT; UL_LOAD_PERCENT; RTT_TIMESTAMP; REFLECTOR; SEQUENCE; DL_OWD_BASELINE; DL_OWD_US; DL_OWD_DELTA_EWMA_US; DL_OWD_DELTA_US; DL_ADJ_DELAY_THR; UL_OWD_BASELINE; UL_OWD_US; UL_OWD_DELTA_EWMA_US; UL_OWD_DELTA_US; UL_ADJ_DELAY_THR; SUM_DL_DELAYS; SUM_UL_DELAYS; DL_LOAD_CONDITION; UL_LOAD_CONDITION; CAKE_DL_RATE_KBPS; CAKE_UL_RATE_KBPS"
 	((log_to_file)) && printf '%s\n' "${header}" >> ${log_file_path}
 	((terminal)) && printf '%s\n' "${header}"

	header="LOAD_HEADER; LOG_DATETIME; LOG_TIMESTAMP; PROC_TIME_US; DL_ACHIEVED_RATE_KBPS; UL_ACHIEVED_RATE_KBPS; CAKE_DL_RATE_KBPS; CAKE_UL_RATE_KBPS"
 	((log_to_file)) && printf '%s\n' "${header}" >> ${log_file_path}
 	((terminal)) && printf '%s\n' "${header}"

	header="REFLECTOR_HEADER; LOG_DATETIME; LOG_TIMESTAMP; PROC_TIME_US; REFLECTOR; DL_MIN_BASELINE_US; DL_BASELINE_US; DL_BASELINE_DELTA_US; DL_BASELINE_DELTA_THR_US; DL_MIN_DELTA_EWMA_US; DL_DELTA_EWMA_US; DL_DELTA_EWMA_DELTA_US; DL_DELTA_EWMA_DELTA_THR; UL_MIN_BASELINE_US; UL_BASELINE_US; UL_BASELINE_DELTA_US; UL_BASELINE_DELTA_THR_US; UL_MIN_DELTA_EWMA_US; UL_DELTA_EWMA_US; UL_DELTA_EWMA_DELTA_US; UL_DELTA_EWMA_DELTA_THR"
 	((log_to_file)) && printf '%s\n' "${header}" >> ${log_file_path}
 	((terminal)) && printf '%s\n' "${header}"
}


# MAINTAIN_LOG_FILE + HELPER FUNCTIONS
rotate_log_file()
{
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	[[ -f ${log_file_path} ]] && mv ${log_file_path} ${log_file_path}.old
	((output_processing_stats)) && print_headers
}


export_log_file()
{
	local export_type=${1}
	
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	case ${export_type} in

		default)
			printf -v log_file_export_datetime '%(%Y_%m_%d_%H_%M_%S)T'
        		log_msg "DEBUG" "Exporting log file with regular path: ${log_file_path/.log/_${log_file_export_datetime}.log}"
        		log_file_export_path="${log_file_path/.log/_${log_file_export_datetime}.log}"
        		;;

		alternative)
			log_msg "DEBUG" "Exporting log file with alternative path: ${log_file_export_alternative_path}"
        		log_file_export_path=${log_file_export_alternative_path}
			;;

		*)
			log_msg "DEBUG" "Unrecognised export type. Not exporting log file."
			return
		;;
	esac

	# Now export with or without compression to the appropriate export path
	if ((log_file_export_compress)); then
		if [[ -f ${log_file_path}.old ]]; then 
			gzip -c ${log_file_path}.old > ${log_file_export_path}.gz
			gzip -c ${log_file_path} >> ${log_file_export_path}.gz
		else
			gzip -c ${log_file_path} > ${log_file_export_path}.gz
		fi
	else
		if [[ -f ${log_file_path}.old ]]; then 
			cp ${log_file_path}.old ${log_file_export_path}.old
			cat ${log_file_path} >> ${log_file_export_path}
		else
			cp ${log_file_path} ${log_file_export_path}
		fi
	fi
}



flush_log_fifo()
{
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"
	while read -t 0.01 log_line
	do
		printf '%s\n' "${log_line}" >> ${log_file_path}		
	done<${run_path}/log_fifo
}

get_log_file_size_bytes()
{
	read log_file_size_bytes< <(du -b ${log_file_path})
	log_file_size_bytes=${log_file_size_bytes//[!0-9]/}
	! [[ ${log_file_size_bytes} =~ ^[0-9]+$ ]] && log_file_size_bytes=0
}

kill_maintain_log_file()
{
	trap - TERM EXIT
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"
	flush_log_fifo
	exit
}

maintain_log_file()
{
	trap '' INT
	trap "kill_maintain_log_file" TERM EXIT

	trap 'export_log_file "default"' USR1
	trap 'export_log_file "alternative"' USR2

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	t_log_file_start_us=${EPOCHREALTIME/./}

	get_log_file_size_bytes

	while true
	do
		while read log_line
		do

			printf '%s\n' "${log_line}" >> ${log_file_path}		

			# Verify log file size < configured maximum
			# The following two lines with costly call to 'du':
			# 	read log_file_size_bytes< <(du -b ${log_file_path}/cake-autorate.log)
			# 	log_file_size_bytes=${log_file_size_bytes//[!0-9]/}
			# can be more efficiently handled with this line:
			((log_file_size_bytes=log_file_size_bytes+${#log_line}+1))

			# Verify log file time < configured maximum
			if (( (${EPOCHREALTIME/./}-t_log_file_start_us) > log_file_max_time_us )); then
			
				log_msg "DEBUG" "log file maximum time: ${log_file_max_time_mins} minutes has elapsed so rotating log file"
				break
			fi

			if (( log_file_size_bytes > log_file_max_size_bytes )); then

				log_file_size_KB=$((log_file_size_bytes/1024))
				log_msg "DEBUG" "log file size: ${log_file_size_KB} KB has exceeded configured maximum: ${log_file_max_size_KB} KB so rotating log file"
				break
			fi

		done<${run_path}/log_fifo
		
		flush_log_fifo
		rotate_log_file
		t_log_file_start_us=${EPOCHREALTIME/./}
		get_log_file_size_bytes

	done
}

get_next_shaper_rate() 
{
	local min_shaper_rate_kbps=${1}
	local base_shaper_rate_kbps=${2}
	local max_shaper_rate_kbps=${3}
	local achieved_rate_kbps=${4}
	local load_condition=${5}
	local t_next_rate_us=${6}
	local -n t_last_bufferbloat_us=${7}
	local -n t_last_decay_us=${8}
	local -n shaper_rate_kbps=${9}

	case ${load_condition} in

		# upload Starlink satelite switching compensation, so drop down to minimum rate for upload through switching period
		ul*sss)
			shaper_rate_kbps=${min_shaper_rate_kbps}
			;;
		# download Starlink satelite switching compensation, so drop down to base rate for download through switching period
		dl*sss)
			shaper_rate_kbps=$(( shaper_rate_kbps > base_shaper_rate_kbps ? base_shaper_rate_kbps : shaper_rate_kbps ))
			;;
		# bufferbloat detected, so decrease the rate providing not inside bufferbloat refractory period
		*bb*)
			if (( t_next_rate_us > (t_last_bufferbloat_us+bufferbloat_refractory_period_us) )); then
				adjusted_achieved_rate_kbps=$(( (achieved_rate_kbps*achieved_rate_adjust_down_bufferbloat)/1000 )) 
				adjusted_shaper_rate_kbps=$(( (shaper_rate_kbps*shaper_rate_adjust_down_bufferbloat)/1000 )) 
				shaper_rate_kbps=$(( adjusted_achieved_rate_kbps > min_shaper_rate_kbps && adjusted_achieved_rate_kbps < adjusted_shaper_rate_kbps ? adjusted_achieved_rate_kbps : adjusted_shaper_rate_kbps ))
				t_last_bufferbloat_us=${EPOCHREALTIME/./}
			fi
			;;
            	# high load, so increase rate providing not inside bufferbloat refractory period 
		*high*)	
			if (( t_next_rate_us > (t_last_bufferbloat_us+bufferbloat_refractory_period_us) )); then
				shaper_rate_kbps=$(( (shaper_rate_kbps*shaper_rate_adjust_up_load_high)/1000 ))
			fi
			;;
		# low or idle load, so determine whether to decay down towards base rate, decay up towards base rate, or set as base rate
		*low*|*idle*)
			if (( t_next_rate_us > (t_last_decay_us+decay_refractory_period_us) )); then

	                	if ((shaper_rate_kbps > base_shaper_rate_kbps)); then
					decayed_shaper_rate_kbps=$(( (shaper_rate_kbps*shaper_rate_adjust_down_load_low)/1000 ))
					shaper_rate_kbps=$(( decayed_shaper_rate_kbps > base_shaper_rate_kbps ? decayed_shaper_rate_kbps : base_shaper_rate_kbps))
				elif ((shaper_rate_kbps < base_shaper_rate_kbps)); then
        			        decayed_shaper_rate_kbps=$(( (shaper_rate_kbps*shaper_rate_adjust_up_load_low)/1000 ))
					shaper_rate_kbps=$(( decayed_shaper_rate_kbps < base_shaper_rate_kbps ? decayed_shaper_rate_kbps : base_shaper_rate_kbps))
                		fi

				t_last_decay_us=${EPOCHREALTIME/./}
			fi
			;;
	esac
        # make sure to only return rates between cur_min_rate and cur_max_rate
        ((shaper_rate_kbps < min_shaper_rate_kbps)) && shaper_rate_kbps=${min_shaper_rate_kbps}
        ((shaper_rate_kbps > max_shaper_rate_kbps)) && shaper_rate_kbps=${max_shaper_rate_kbps}
}

monitor_achieved_rates()
{
	trap '' INT

	# track rx and tx bytes transfered and divide by time since last update
	# to determine achieved dl and ul transfer rates

	local rx_bytes_path=${1}
	local tx_bytes_path=${2}
	local monitor_achieved_rates_interval_us=${3} # (microseconds)

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	compensated_monitor_achieved_rates_interval_us=${monitor_achieved_rates_interval_us}

	[[ -f ${rx_bytes_path} ]] && { read -r prev_rx_bytes < ${rx_bytes_path}; } 2> /dev/null || prev_rx_bytes=0
        [[ -f ${tx_bytes_path} ]] && { read -r prev_tx_bytes < ${tx_bytes_path}; } 2> /dev/null || prev_tx_bytes=0

	while true
	do
        	t_start_us=${EPOCHREALTIME/./}

		# If rx/tx bytes file exists, read it in, otherwise set to prev_bytes
		# This addresses interfaces going down and back up
       		[[ -f ${rx_bytes_path} ]] && { read -r rx_bytes < ${rx_bytes_path}; } 2> /dev/null || rx_bytes=${prev_rx_bytes}
       		[[ -f ${tx_bytes_path} ]] && { read -r tx_bytes < ${tx_bytes_path}; } 2> /dev/null || tx_bytes=${prev_tx_bytes}

        	dl_achieved_rate_kbps=$(( ((8000*(rx_bytes - prev_rx_bytes)) / compensated_monitor_achieved_rates_interval_us ) ))
       		ul_achieved_rate_kbps=$(( ((8000*(tx_bytes - prev_tx_bytes)) / compensated_monitor_achieved_rates_interval_us ) ))
		
		((dl_achieved_rate_kbps<0)) && dl_achieved_rate_kbps=0
		((ul_achieved_rate_kbps<0)) && ul_achieved_rate_kbps=0
	
		printf '%s' "${dl_achieved_rate_kbps}" > ${run_path}/dl_achieved_rate_kbps
		printf '%s' "${ul_achieved_rate_kbps}" > ${run_path}/ul_achieved_rate_kbps
		
		if ((output_load_stats)); then 
		
			concurrent_read_integer dl_shaper_rate_kbps ${run_path}/dl_shaper_rate_kbps	
			concurrent_read_integer ul_shaper_rate_kbps ${run_path}/ul_shaper_rate_kbps	
			printf -v load_stats '%s; %s; %s; %s; %s' ${EPOCHREALTIME} ${dl_achieved_rate_kbps} ${ul_achieved_rate_kbps} ${dl_shaper_rate_kbps} ${ul_shaper_rate_kbps}
			log_msg "LOAD" "${load_stats}"
		fi

		prev_rx_bytes=${rx_bytes}
       		prev_tx_bytes=${tx_bytes}

		# read in the max_wire_packet_rtt_us
		concurrent_read_integer max_wire_packet_rtt_us ${run_path}/max_wire_packet_rtt_us

		compensated_monitor_achieved_rates_interval_us=$(( ((monitor_achieved_rates_interval_us>(10*max_wire_packet_rtt_us) )) ? monitor_achieved_rates_interval_us : 10*max_wire_packet_rtt_us ))

		sleep_remaining_tick_time ${t_start_us} ${compensated_monitor_achieved_rates_interval_us}		
	done
}

get_loads()
{
	# read in the dl/ul achived rates and determine the loads

	concurrent_read_integer dl_achieved_rate_kbps ${run_path}/dl_achieved_rate_kbps 
	concurrent_read_integer ul_achieved_rate_kbps ${run_path}/ul_achieved_rate_kbps 

	dl_load_percent=$(( (100*dl_achieved_rate_kbps)/dl_shaper_rate_kbps ))
	ul_load_percent=$(( (100*ul_achieved_rate_kbps)/ul_shaper_rate_kbps ))

	printf '%s' "${dl_load_percent}" > ${run_path}/dl_load_percent
	printf '%s' "${ul_load_percent}" > ${run_path}/ul_load_percent
}

classify_load()
{
	# classify the load according to high/low/idle and add _delayed if delayed
	# thus ending up with high_delayed, low_delayed, etc.
	local load_percent=${1}
	local achieved_rate_kbps=${2}
	local bufferbloat_detected=${3}
	local -n load_condition=${4}
	
	if (( load_percent > high_load_thr_percent )); then
		load_condition="high"  
	elif (( achieved_rate_kbps > connection_active_thr_kbps )); then
		load_condition="low"
	else 
		load_condition="idle"
	fi
	
	((bufferbloat_detected)) && load_condition=${load_condition}"_bb"
		
	if ((sss_compensation)); then
		for sss_time_us in "${sss_times_us[@]}"
		do
			((timestamp_usecs_past_minute=${EPOCHREALTIME/./}%60000000))
			if (( (timestamp_usecs_past_minute > (sss_time_us-sss_compensation_pre_duration_us)) && (timestamp_usecs_past_minute < (sss_time_us+sss_compensation_post_duration_us)) )); then
				load_condition=${load_condition}"_sss"
				break
			fi
		done			
	fi
}

# MAINTAIN PINGERS + ASSOCIATED HELPER FUNCTIONS



# GENERIC PINGER START AND STOP FUNCTIONS






# END OF GENERIC PINGER START AND STOP FUNCTIONS




set_cake_rate()
{
	local interface=${1}
	local shaper_rate_kbps=${2}
	local adjust_shaper_rate=${3}
	local -n time_rate_set_us=${4}
	
	((output_cake_changes)) && log_msg "SHAPER" "tc qdisc change root dev ${interface} cake bandwidth ${shaper_rate_kbps}Kbit"

	if ((adjust_shaper_rate)); then

		if ((debug)); then
			tc qdisc change root dev ${interface} cake bandwidth ${shaper_rate_kbps}Kbit
		else
			tc qdisc change root dev ${interface} cake bandwidth ${shaper_rate_kbps}Kbit 2> /dev/null
		fi

		time_rate_set_us=${EPOCHREALTIME/./}

	else
		((output_cake_changes)) && log_msg "DEBUG" "adjust_shaper_rate set to 0 in config, so skipping the tc qdisc change call"
	fi
}

set_shaper_rates()
{
	if (( dl_shaper_rate_kbps != last_dl_shaper_rate_kbps || ul_shaper_rate_kbps != last_ul_shaper_rate_kbps )); then 
     	
		# fire up tc in each direction if there are rates to change, and if rates change in either direction then update max wire calcs
		if (( dl_shaper_rate_kbps != last_dl_shaper_rate_kbps )); then 
			set_cake_rate ${dl_if} ${dl_shaper_rate_kbps} adjust_dl_shaper_rate t_prev_dl_rate_set_us
			printf '%s' "${dl_shaper_rate_kbps}" > ${run_path}/dl_shaper_rate_kbps
		 	last_dl_shaper_rate_kbps=${dl_shaper_rate_kbps};
		fi
		if (( ul_shaper_rate_kbps != last_ul_shaper_rate_kbps )); then 
			set_cake_rate ${ul_if} ${ul_shaper_rate_kbps} adjust_ul_shaper_rate t_prev_ul_rate_set_us
			printf '%s' "${ul_shaper_rate_kbps}" > ${run_path}/ul_shaper_rate_kbps
			last_ul_shaper_rate_kbps=${ul_shaper_rate_kbps}
		fi

		update_max_wire_packet_compensation
	fi
}

set_min_shaper_rates()
{
	log_msg "DEBUG" "Enforcing minimum shaper rates."
	dl_shaper_rate_kbps=${min_dl_shaper_rate_kbps}
	ul_shaper_rate_kbps=${min_ul_shaper_rate_kbps}
	set_shaper_rates
}

get_max_wire_packet_size_bits()
{
	local interface=${1}
	local -n max_wire_packet_size_bits=${2}
 
	read -r max_wire_packet_size_bits < "/sys/class/net/${interface}/mtu" 
	[[ $(tc qdisc show dev ${interface}) =~ (atm|noatm)[[:space:]]overhead[[:space:]]([0-9]+) ]]
	[[ ! -z "${BASH_REMATCH[2]}" ]] && max_wire_packet_size_bits=$(( 8*(max_wire_packet_size_bits+BASH_REMATCH[2]) )) 
	# atm compensation = 53*ceil(X/48) bytes = 8*53*((X+8*(48-1)/(8*48)) bits = 424*((X+376)/384) bits
	[[ "${BASH_REMATCH[1]}" == "atm" ]] && max_wire_packet_size_bits=$(( 424*((${max_wire_packet_size_bits}+376)/384) ))
}

update_max_wire_packet_compensation()
{
	# Compensate for delays imposed by active traffic shaper
	# This will serve to increase the delay thr at rates below around 12Mbit/s

	# compensated OWD delay thresholds in microseconds
	compensated_dl_delay_thr_us=$(( dl_delay_thr_us + (1000*dl_max_wire_packet_size_bits)/dl_shaper_rate_kbps ))
	compensated_ul_delay_thr_us=$(( ul_delay_thr_us + (1000*ul_max_wire_packet_size_bits)/ul_shaper_rate_kbps ))
	printf '%s' "${compensated_dl_delay_thr_us}" > ${run_path}/compensated_dl_delay_thr_us
	printf '%s' "${compensated_ul_delay_thr_us}" > ${run_path}/compensated_ul_delay_thr_us

	# determine and write out ${max_wire_packet_rtt_us}
	max_wire_packet_rtt_us=$(( (1000*dl_max_wire_packet_size_bits)/dl_shaper_rate_kbps + (1000*ul_max_wire_packet_size_bits)/ul_shaper_rate_kbps ))
	printf '%s' "${max_wire_packet_rtt_us}" > ${run_path}/max_wire_packet_rtt_us
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

verify_ifs_up()
{
	# Check the rx/tx paths exist and give extra time for ifb's to come up if needed
	# This will block if ifs never come up
	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	while [[ ! -f ${rx_bytes_path} || ! -f ${tx_bytes_path} ]]
	do
		[[ ! -f ${rx_bytes_path} ]] && log_msg "DEBUG" "Warning: The configured download interface: '${dl_if}' does not appear to be present. Waiting ${if_up_check_interval_s} seconds for the interface to come up." 
		[[ ! -f ${tx_bytes_path} ]] && log_msg "DEBUG" "Warning: The configured upload interface: '${ul_if}' does not appear to be present. Waiting ${if_up_check_interval_s} seconds for the interface to come up." 
		sleep_s ${if_up_check_interval_s}
	done
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

randomize_array()
{
	local -n array=${1}

	log_msg "DEBUG" "Starting: ${FUNCNAME[0]} with PID: ${BASHPID}"

	subset=(${array[@]})
	array=()
	for ((set=${#subset[@]}; set>0; set--))
	do
		idx=$((RANDOM%set))
		array+=("${subset[idx]}")
		unset subset[idx]
        	subset=(${subset[@]})
	done
}

ewma_iteration()
{
	local value=${1}
	local alpha=${2} # alpha must be scaled by factor of 1000000
	local -n ewma=${3}

	prev_ewma=${ewma}
	ewma=$(( (alpha*value+(1000000-alpha)*prev_ewma)/1000000 ))
}


# ======= Start of the Main Routine ========
# get the directory where this script (and its helps reside)
# and source autorate_functions.sh
cur_filename="$( readlink -f -- "${0}" )"
autorate_code_dir="$( dirname -- "${cur_filename}" )"
. ${autorate_code_dir}/cake-autorate_common_functions.sh
cur_script_name="$( basename -- ${0} )"



[[ -t 1 ]] && export terminal=1

type logger &> /dev/null && export use_logger=1 || export use_logger=0 # only perform the test once.

log_file_path=/var/log/cake-autorate.log

# redirect stderr to log_msg
coproc log_stderr { exec >/proc/$PPID/fd/1; while read error; do log_msg "ERROR" "$error"; done; }
exec 2>&${log_stderr[1]}

# *** WARNING: take great care if attempting to alter the run_path! ***
# *** cake-autorate issues mkdir -p ${run_path} and rm -r ${run_path} on exit. ***
run_path=/var/run/cake-autorate/

# cake-autorate first argument is config file path
if [[ ! -z ${1} ]]; then
	export config_path=${1}
else
	export config_path=/root/cake-autorate/cake-autorate_config.primary.sh
fi

if [[ ! -f "${config_path}" ]]; then
	log_msg "ERROR" "No config file found. Exiting now."
	exit
fi

# get all the variables from the config file
. ${config_path}

if [[ ${config_file_check} != "cake-autorate" ]]; then
	log_msg "ERROR" "Config file error. Please check config file entries." 
	exit
fi

if [[ ${config_path} =~ cake-autorate_config\.(.*)\.sh ]]; then
	export instance_id=${BASH_REMATCH[1]}
	export run_path=/var/run/cake-autorate/${instance_id}
else
	log_msg "ERROR" "Instance identifier 'X' set by cake-autorate_config.X.sh cannot be empty. Exiting now."
	exit
fi

if [[ ! -z "${log_file_path_override}" ]]; then 
	if [[ ! -d ${log_file_path_override} ]]; then
		broken_log_file_path_override=${log_file_path_override}
		log_file_path=/var/log/cake-autorate${instance_id:+.${instance_id}}.log
		log_msg "ERROR" "Log file path override: '${broken_log_file_path_override}' does not exist. Exiting now."
		exit
	fi
	export log_file_path=${log_file_path_override}/cake-autorate${instance_id:+.${instance_id}}.log
else
	export log_file_path=/var/log/cake-autorate${instance_id:+.${instance_id}}.log
fi

rotate_log_file # rotate here to force header prints at top of log file

log_msg "SYSLOG" "Starting cake-autorate with PID: ${BASHPID} and config: ${config_path}"
#log_msg "DEBUG" "${cur_script_name}: autorate_code_dir: ${autorate_code_dir}"


# ${run_path}/ is used to store temporary files
# it should not exist on startup so if it does exit, else create the directory
if [[ -d ${run_path} ]]; then
        log_msg "ERROR" "${run_path} already exists. Is another instance running? Exiting script."
        trap - INT TERM EXIT
        exit
else
        mkdir -p ${run_path}
fi

mkfifo ${run_path}/sleep_fifo
exec {fd}<> ${run_path}/sleep_fifo

no_reflectors=${#reflectors[@]} 

# Check ping binary exists
command -v "${pinger_binary}" &> /dev/null || { log_msg "ERROR" "ping binary ${ping_binary} does not exist. Exiting script."; exit; }

# Check no_pingers <= no_reflectors
(( no_pingers > no_reflectors )) && { log_msg "ERROR" "number of pingers cannot be greater than number of reflectors. Exiting script."; exit; }

# Check dl/if interface not the same
[[ ${dl_if} == ${ul_if} ]] && { log_msg "ERROR" "download interface and upload interface are both set to: '${dl_if}', but cannot be the same. Exiting script."; exit; }

# Check bufferbloat detection threshold not greater than window length
(( ${bufferbloat_detection_thr} > ${bufferbloat_detection_window} )) && { log_msg "ERROR" "bufferbloat_detection_thr cannot be greater than bufferbloat_detection_window. Exiting script."; exit; }

# Passed error checks 

if ((${log_to_file})); then
	log_file_max_time_us=$((${log_file_max_time_mins}*60000000))
	log_file_max_size_bytes=$((${log_file_max_size_KB}*1024))
	mkfifo ${run_path}/log_fifo
	exec {fd}<> ${run_path}/log_fifo
	maintain_log_file&
	maintain_log_file_pid=${!}
	log_msg "DEBUG" "Started maintain log file process with PID: ${maintain_log_file_pid}"
	echo ${maintain_log_file_pid} > ${run_path}/maintain_log_file_pid
fi

# test if stdout is a tty (terminal)
if ! ((terminal)); then
	echo "stdout not a terminal so redirecting output to: ${log_file_path}"
	((log_to_file)) && exec 1> ${run_path}/log_fifo
fi

if (( ${debug} )) ; then
	log_msg "DEBUG" "CAKE-autorate version: ${cake_autorate_version}"
	log_msg "DEBUG" "config_path: ${config_path}"
	log_msg "DEBUG" "run_path: ${run_path}"
	log_msg "DEBUG" "log_file_path: ${log_file_path}"
	log_msg "DEBUG" "pinger_binary:${pinger_binary}"
	log_msg "DEBUG" "download interface: ${dl_if} (${min_dl_shaper_rate_kbps} / ${base_dl_shaper_rate_kbps} / ${max_dl_shaper_rate_kbps})"
	log_msg "DEBUG" "upload interface: ${ul_if} (${min_ul_shaper_rate_kbps} / ${base_ul_shaper_rate_kbps} / ${max_ul_shaper_rate_kbps})"
	log_msg "DEBUG" "rx_bytes_path: ${rx_bytes_path}"
	log_msg "DEBUG" "tx_bytes_path: ${tx_bytes_path}"
fi

# Check interfaces are up and wait if necessary for them to come up
verify_ifs_up
# Initialize variables

# Convert human readable parameters to values that work with integer arithmetic
printf -v dl_delay_thr_us %.0f "${dl_delay_thr_ms}e3"
printf -v ul_delay_thr_us %.0f "${ul_delay_thr_ms}e3"
#printf -v alpha_baseline_increase %.0f "${alpha_baseline_increase}e6"
#printf -v alpha_baseline_decrease %.0f "${alpha_baseline_decrease}e6"   
#printf -v alpha_delta_ewma %.0f "${alpha_delta_ewma}e6"   
printf -v achieved_rate_adjust_down_bufferbloat %.0f "${achieved_rate_adjust_down_bufferbloat}e3"
printf -v shaper_rate_adjust_down_bufferbloat %.0f "${shaper_rate_adjust_down_bufferbloat}e3"
printf -v shaper_rate_adjust_up_load_high %.0f "${shaper_rate_adjust_up_load_high}e3"
printf -v shaper_rate_adjust_down_load_low %.0f "${shaper_rate_adjust_down_load_low}e3"
printf -v shaper_rate_adjust_up_load_low %.0f "${shaper_rate_adjust_up_load_low}e3"
printf -v high_load_thr_percent %.0f "${high_load_thr}e2"
#printf -v reflector_ping_interval_ms %.0f "${reflector_ping_interval_s}e3"
printf -v reflector_ping_interval_us %.0f "${reflector_ping_interval_s}e6"
printf -v monitor_achieved_rates_interval_us %.0f "${monitor_achieved_rates_interval_ms}e3"
printf -v sustained_idle_sleep_thr_us %.0f "${sustained_idle_sleep_thr_s}e6"
printf -v reflector_response_deadline_us %.0f "${reflector_response_deadline_s}e6"
#printf -v reflector_owd_baseline_delta_thr_us %.0f "${reflector_owd_baseline_delta_thr_ms}e3"
#printf -v reflector_owd_delta_ewma_delta_thr_us %.0f "${reflector_owd_delta_ewma_delta_thr_ms}e3"
printf -v startup_wait_us %.0f "${startup_wait_s}e6"
printf -v global_ping_response_timeout_us %.0f "${global_ping_response_timeout_s}e6"
printf -v bufferbloat_refractory_period_us %.0f "${bufferbloat_refractory_period_ms}e3"
printf -v decay_refractory_period_us %.0f "${decay_refractory_period_ms}e3"

for (( i=0; i<${#sss_times_s[@]}; i++ ));
do
	printf -v sss_times_us[i] %.0f\\n "${sss_times_s[i]}e6"
done
printf -v sss_compensation_pre_duration_us %.0f "${sss_compensation_pre_duration_ms}e3"
printf -v sss_compensation_post_duration_us %.0f "${sss_compensation_post_duration_ms}e3"

export ping_response_interval_us=$(( reflector_ping_interval_us/no_pingers ))
export ping_response_interval_ms=$(( ping_response_interval_us/1000 ))

stall_detection_timeout_us=$(( stall_detection_thr*ping_response_interval_us ))
stall_detection_timeout_s=000000${stall_detection_timeout_us}
stall_detection_timeout_s=$(( 10#${stall_detection_timeout_s::-6})).${stall_detection_timeout_s: -6}

concurrent_read_integer_interval_us=$((ping_response_interval_us/4))

dl_shaper_rate_kbps=${base_dl_shaper_rate_kbps}
ul_shaper_rate_kbps=${base_ul_shaper_rate_kbps}

last_dl_shaper_rate_kbps=0
last_ul_shaper_rate_kbps=0

get_max_wire_packet_size_bits ${dl_if} dl_max_wire_packet_size_bits  
get_max_wire_packet_size_bits ${ul_if} ul_max_wire_packet_size_bits

set_shaper_rates

update_max_wire_packet_compensation

t_start_us=${EPOCHREALTIME/./}
t_end_us=${EPOCHREALTIME/./}
t_prev_ul_rate_set_us=${t_start_us}
t_prev_dl_rate_set_us=${t_start_us}
t_ul_last_bufferbloat_us=${t_start_us}
t_ul_last_decay_us=${t_start_us}
t_dl_last_bufferbloat_us=${t_start_us}
t_dl_last_decay_us=${t_start_us}

t_sustained_connection_idle_us=0

declare -a dl_delays=( $(for i in {1..${bufferbloat_detection_window}}; do echo 0; done) )
declare -a ul_delays=( $(for i in {1..${bufferbloat_detection_window}}; do echo 0; done) )

delays_idx=0
sum_dl_delays=0
sum_ul_delays=0

if ((debug)); then
	if (( bufferbloat_refractory_period_us < (bufferbloat_detection_window*ping_response_interval_us) )); then
		log_msg "DEBUG" "Warning: bufferbloat refractory period: ${bufferbloat_refractory_period_us} us."
		log_msg "DEBUG" "Warning: but expected time to overwrite samples in bufferbloat detection window is: $((${bufferbloat_detection_window}*${ping_response_interval_us})) us." 
		log_msg "DEBUG" "Warning: Consider increasing bufferbloat refractory period or decreasing bufferbloat detection window."
	fi
	if (( reflector_response_deadline_us < 2*reflector_ping_interval_us )); then 
		log_msg "DEBUG" "Warning: reflector_response_deadline_s < 2*reflector_ping_interval_s"
		log_msg "DEBUG" "Warning: consider setting an increased reflector_response_deadline."
	fi
fi

# Randomize reflectors array providing randomize_reflectors set to 1
((randomize_reflectors)) && randomize_array reflectors

# Wait if ${startup_wait_s} > 0
if ((startup_wait_us>0)); then
        log_msg "DEBUG" "Waiting ${startup_wait_s} seconds before startup."
        sleep_us ${startup_wait_us}
fi

# Initiate achieved rate monitor
monitor_achieved_rates ${rx_bytes_path} ${tx_bytes_path} ${monitor_achieved_rates_interval_us}&
monitor_achieved_rates_pid=${!}
	
printf '%s' "0" > ${run_path}/dl_load_percent
printf '%s' "0" > ${run_path}/ul_load_percent

mkfifo ${run_path}/ping_fifo
exec {fd}<> ${run_path}/ping_fifo

# cake-autorate_maintain_pingers.sh will source the config file to get access to reflectors
${autorate_code_dir}/cake-autorate_maintain_pingers.sh ${config_path} &
maintain_pingers_pid=${!}
log_process_cmdline maintain_pingers_pid
log_msg "DEBUG" "${cur_script_name}: maintain_pingers_pid: ${maintain_pingers_pid}"


log_msg "INFO" "Started cake-autorate with PID: ${BASHPID} and config: ${config_path}"

while true
do
	while read -t ${stall_detection_timeout_s} timestamp reflector seq dl_owd_baseline_us dl_owd_us dl_owd_delta_ewma_us dl_owd_delta_us ul_owd_baseline_us ul_owd_us ul_owd_delta_ewma_us ul_owd_delta_us
	do 
		t_start_us=${EPOCHREALTIME/./}
		if (( (t_start_us - 10#"${timestamp//[.]}")>500000 )); then
			log_msg "DEBUG" "processed response from [${reflector}] that is > 500ms old. Skipping." 
			continue
		fi

		# Keep track of number of dl delays across detection window
		# .. for download:
		(( dl_delays[delays_idx] )) && ((sum_dl_delays--))
		dl_delays[delays_idx]=$(( dl_owd_delta_us > compensated_dl_delay_thr_us ? 1 : 0 ))
		((dl_delays[delays_idx])) && ((sum_dl_delays++))
		# .. for upload
		(( ul_delays[delays_idx] )) && ((sum_ul_delays--))
		ul_delays[delays_idx]=$(( ul_owd_delta_us > compensated_ul_delay_thr_us ? 1 : 0 ))
		((ul_delays[delays_idx])) && ((sum_ul_delays++))
	 	# .. and move index on	
		(( delays_idx=(delays_idx+1)%bufferbloat_detection_window ))

		dl_bufferbloat_detected=$(( ((sum_dl_delays >= bufferbloat_detection_thr)) ? 1 : 0 ))
		ul_bufferbloat_detected=$(( ((sum_ul_delays >= bufferbloat_detection_thr)) ? 1 : 0 ))

		get_loads

		classify_load ${dl_load_percent} ${dl_achieved_rate_kbps} ${dl_bufferbloat_detected} dl_load_condition
		classify_load ${ul_load_percent} ${ul_achieved_rate_kbps} ${ul_bufferbloat_detected} ul_load_condition
	
		dl_load_condition="dl_"${dl_load_condition}
		ul_load_condition="ul_"${ul_load_condition}

		get_next_shaper_rate ${min_dl_shaper_rate_kbps} ${base_dl_shaper_rate_kbps} ${max_dl_shaper_rate_kbps} ${dl_achieved_rate_kbps} ${dl_load_condition} ${t_start_us} t_dl_last_bufferbloat_us t_dl_last_decay_us dl_shaper_rate_kbps
		get_next_shaper_rate ${min_ul_shaper_rate_kbps} ${base_ul_shaper_rate_kbps} ${max_ul_shaper_rate_kbps} ${ul_achieved_rate_kbps} ${ul_load_condition} ${t_start_us} t_ul_last_bufferbloat_us t_ul_last_decay_us ul_shaper_rate_kbps

		set_shaper_rates

		if (( output_processing_stats )); then 
			printf -v processing_stats '%s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s; %s' ${EPOCHREALTIME} ${dl_achieved_rate_kbps} ${ul_achieved_rate_kbps} ${dl_load_percent} ${ul_load_percent} ${timestamp} ${reflector} ${seq} ${dl_owd_baseline_us} ${dl_owd_us} ${dl_owd_delta_ewma_us} ${dl_owd_delta_us} ${compensated_dl_delay_thr_us} ${ul_owd_baseline_us} ${ul_owd_us} ${ul_owd_delta_ewma_us} ${ul_owd_delta_us} ${compensated_ul_delay_thr_us} ${sum_dl_delays} ${sum_ul_delays} ${dl_load_condition} ${ul_load_condition} ${dl_shaper_rate_kbps} ${ul_shaper_rate_kbps}
			log_msg "DATA" "${processing_stats}"
		fi

		# If base rate is sustained, increment sustained base rate timer (and break out of processing loop if enough time passes)
		if (( enable_sleep_function )); then
			if [[ ${dl_load_condition} == *idle* && ${ul_load_condition} == *idle* ]]; then
				((t_sustained_connection_idle_us += (${EPOCHREALTIME/./}-t_end_us) ))
				((t_sustained_connection_idle_us > sustained_idle_sleep_thr_us)) && break
			else
				# reset timer
				t_sustained_connection_idle_us=0
			fi
		fi
		
		t_end_us=${EPOCHREALTIME/./}

	done<${run_path}/ping_fifo

	# stall handling procedure
	# PIPESTATUS[0] == 142 corresponds with while loop timeout
	# i.e. no reflector responses within ${stall_detection_thr} * ${ping_response_interval_us}
	if (( PIPESTATUS[0] == 142 )); then


		log_msg "DEBUG" "Warning: no reflector response within: ${stall_detection_timeout_s} seconds. Checking for loads."

		get_loads

		log_msg "DEBUG" "load check is: ((${dl_achieved_rate_kbps} kbps > ${connection_stall_thr_kbps} kbps && ${ul_achieved_rate_kbps} kbps > ${connection_stall_thr_kbps} kbps))"

		# non-zero load so despite no reflector response within stall interval, the connection not considered to have stalled
		# and therefore resume normal operation
		if (( dl_achieved_rate_kbps > connection_stall_thr_kbps && ul_achieved_rate_kbps > connection_stall_thr_kbps )); then

			log_msg "DEBUG" "load above connection stall threshold so resuming normal operation."
			continue

		fi

		log_msg "DEBUG" "Warning: connection stall detection. Waiting for new ping or increased load"

		# save intial global reflector timestamp to check against for any new reflector response
		concurrent_read_integer initial_reflectors_last_timestamp_us ${run_path}/reflectors_last_timestamp_us

		# send signal USR1 to pause reflector maintenance
		kill -USR1 ${maintain_pingers_pid}

		t_connection_stall_time_us=${EPOCHREALTIME/./}

		global_ping_response_timeout=0

	        # wait until load resumes or ping response received (or global reflector response timeout)
	        while true
	        do
        	        t_start_us=${EPOCHREALTIME/./}
			
			concurrent_read_integer new_reflectors_last_timestamp_us ${run_path}/reflectors_last_timestamp_us
	                get_loads

			if (( new_reflectors_last_timestamp_us != initial_reflectors_last_timestamp_us || ( dl_achieved_rate_kbps > connection_stall_thr_kbps && ul_achieved_rate_kbps > connection_stall_thr_kbps) )); then

				log_msg "DEBUG" "Connection stall ended. Resuming normal operation."

				# send signal USR1 to resume reflector health monitoring to resume reflector rotation
				kill -USR1 ${maintain_pingers_pid}

				# continue main loop (i.e. skip idle/global timeout handling below)
				continue 2
			fi

        	        sleep_remaining_tick_time ${t_start_us} ${reflector_ping_interval_us}

			if (( global_ping_response_timeout==0 && t_start_us > (t_connection_stall_time_us + global_ping_response_timeout_us - stall_detection_timeout_us) )); then 
				log_msg "SYSLOG" "Warning: Configured global ping response timeout: ${global_ping_response_timeout_s} seconds exceeded." 
				((min_shaper_rates_enforcement)) && set_min_shaper_rates
				global_ping_response_timeout=1
			fi
	        done	

	else
		log_msg "DEBUG" "Connection idle. Waiting for minimum load."
		((min_shaper_rates_enforcement)) && set_min_shaper_rates
	fi

	# send signal USR2 to pause maintain_reflectors
	kill -USR2 ${maintain_pingers_pid}

	# reset idle timer
	t_sustained_connection_idle_us=0

	# wait until load increases again
	while true
	do
		t_start_us=${EPOCHREALTIME/./}	
		get_loads

		if (( dl_achieved_rate_kbps > connection_active_thr_kbps || ul_achieved_rate_kbps > connection_active_thr_kbps )); then
			log_msg "DEBUG" "dl achieved rate: ${dl_achieved_rate_kbps} kbps or ul achieved rate: ${ul_achieved_rate_kbps} kbps exceeded connection active threshold: ${connection_active_thr_kbps} kbps. Resuming normal operation."
			break 
		fi
		sleep_remaining_tick_time ${t_start_us} ${reflector_ping_interval_us}
	done

	# send signal USR2 to resume maintain_reflectors
	kill -USR2 ${maintain_pingers_pid}
done
