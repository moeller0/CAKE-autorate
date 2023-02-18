#!/bin/bash
cur_filename="$( readlink -f -- "${0}" )"
autorate_code_dir="$( dirname -- "${cur_filename}" )"



cake_instances=(${autorate_code_dir}/cake-autorate_config*sh)

trap kill_cake_instances INT TERM EXIT

kill_cake_instances()
{
	trap - INT TERM EXIT

	echo "Killing all instances of cake one-by-one now."

	for ((cake_instance=0; cake_instance<${#cake_instances[@]}; cake_instance++))
	do
		kill ${cake_instance_pids[${cake_instance}]}
		wait ${cake_instance_pids[${cake_instance}]}
	done
	kill ${sleep_pid}
}

for cake_instance in "${cake_instances[@]}"
do
	${autorate_code_dir}/cake-autorate.sh $cake_instance&
	cake_instance_pids+=($!)
	cake_instance_list+=(${cake_instance})
done

sleep inf&
sleep_pid+=($!)
wait
