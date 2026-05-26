#! /bin/bash
set -e

ns=(8 12 16)
dims=(4 8 16)
deltas=(16 32)

printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

for n in "${ns[@]}"; do
  for dim in "${dims[@]}"; do
    for delta in "${deltas[@]}"; do
      ./build/fpsi -d $dim -delta $delta -nn $n -p 0 -try 5
      ./build/fpsi -d $dim -delta $delta -nn $n -p 1 -try 5 
      ./build/fpsi -d $dim -delta $delta -nn $n -p 2 -try 5 
      echo 
    done
  done
done


