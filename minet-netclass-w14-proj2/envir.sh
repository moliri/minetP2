#! /bin/bash

make clean
make

rm ./bin/device_driver2
rm ./bin/reader
rm ./bin/writer

cd ./bin

ln -s /usr/local/eecs340/device_driver2
ln -s /usr/local/eecs340/writer
ln -s /usr/local/eecs340/reader

cd ..

chmod a+w ./fifos/ether2mon
chmod a+w ./fifos/ether2mux


