#!/bin/bash


for i in {1..20}
do
	./custom_client $i &
	sleep 1
done

echo "script exiting"
