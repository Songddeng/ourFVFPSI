#! /bin/bash
set -e

ns=(12)
dims=(8)
deltas=(16 64 256 1024)

printf "[ProType] [Metric] [Dim] [Delta] [Size] [Com.(MB)] [Time(s)]\n"

for n in "${ns[@]}"; do
  for dim in "${dims[@]}"; do
    for delta in "${deltas[@]}"; do
      ./build/fpsi -d $dim -delta $delta -nn $n -p 0 -prefix -try 5
      ./build/fpsi -d $dim -delta $delta -nn $n -p 1 -prefix -try 5
      ./build/fpsi -d $dim -delta $delta -nn $n -p 2 -prefix -try 5
      echo
    done
  done
done


