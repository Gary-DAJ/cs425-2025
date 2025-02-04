#!/bin/bash


for i in {1..20}
do
	./custom_client $i &
done

echo "script exiting"
