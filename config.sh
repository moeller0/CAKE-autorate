#!/bin/bash

# defaults.sh sets up defaults for CAKE-autorate

# defaults.sh is a part of CAKE-autorate
# CAKE-autorate automatically adjusts bandwidth for CAKE in dependence on detected load and RTT

# inspired by @moeller0 (OpenWrt forum)
# initial sh implementation by @Lynx (OpenWrt forum)
# requires packages: iputils-ping, coreutils-date and coreutils-sleep

alpha_OWD_increase=1 # how rapidly baseline OWD is allowed to increase (integer /1000)
alpha_OWD_decrease=900 # how rapidly baseline OWD is allowed to decrease (integer /1000)

debug=0
enable_verbose_output=0 # enable (1) or disable (0) output monitoring lines showing bandwidth changes

ul_if=wan # upload interface
dl_if=veth-lan # download interface

min_dl_rate=20000 # minimum bandwidth for download
base_dl_rate=25000 # steady state bandwidth for download
max_dl_rate=80000 # maximum bandwidth for download

min_ul_rate=25000 # minimum bandwidth for upload
base_ul_rate=30000 # steady state bandwidth for upload
max_ul_rate=35000 # maximum bandwidth for upload

alpha_OWD_increase=1 # how rapidly baseline RTT is allowed to increase (integer /1000)
alpha_OWD_decrease=900 # how rapidly baseline RTT is allowed to decrease (integer /1000)

rate_adjust_OWD_spike=50 # how rapidly to reduce bandwidth upon detection of bufferbloat (integer /1000)
rate_adjust_load_high=10 # how rapidly to increase bandwidth upon high load detected (integer /1000)
rate_adjust_load_low=25 # how rapidly to return to base rate upon low load detected (integer /1000)

high_load_thr=50 # % of currently set bandwidth for detecting high load (integer /100)

delay_buffer_len=4 # size of delay detection window
delay_thr=15 # extent of delay to classify as an offence 
detection_thr=2 # number of offences within window to classify reflector path delayed
reflector_thr=2 # number of reflectors that need to be delayed to classify bufferbloat

ping_reflector_interval=0.1 # (seconds, e.g. 0.1s)
main_loop_tick_duration=200 # (milliseconds)

bufferbloat_refractory_period=300 # (milliseconds)
decay_refractory_period=5000 # (milliseconds)

ping_sleep_thr=60 # time threshold to put pingers to sleep on sustained ul and dl base rate (seconds)

# verify these are correct using 'cat /sys/class/...'
case "${dl_if}" in
    \veth*)
        rx_bytes_path="/sys/class/net/${dl_if}/statistics/tx_bytes"
        ;;
    \ifb*)
        rx_bytes_path="/sys/class/net/${dl_if}/statistics/tx_bytes"
        ;;
    *)
        rx_bytes_path="/sys/class/net/${dl_if}/statistics/rx_bytes"
        ;;
esac

case "${ul_if}" in
    \veth*)
        tx_bytes_path="/sys/class/net/${ul_if}/statistics/rx_bytes"
        ;;
    \ifb*)
        tx_bytes_path="/sys/class/net/${ul_if}/statistics/rx_bytes"
        ;;
    *)
        tx_bytes_path="/sys/class/net/${ul_if}/statistics/tx_bytes"
        ;;
esac

if (( $debug )) ; then
    echo "rx_bytes_path: $rx_bytes_path"
    echo "tx_bytes_path: $tx_bytes_path"
fi

# list of reflectors to use
reflectors=("1.1.1.1" "1.0.0.1" "8.8.8.8" "8.8.4.4")

no_reflectors=${#reflectors[@]}