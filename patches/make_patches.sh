#!/bin/bash

cd cpython/ && git diff > ../patches/cpython-3.10.12.patch && cd ..
cd dynamorio/ && git diff > ../patches/dynamorio-10.0.patch && cd ..
