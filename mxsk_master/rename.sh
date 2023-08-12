sudo ip link set enp12s0f0np0 down
sudo ip link set enp12s0f0np0 name enp12s0f0
sudo ip link set enp12s0f0 up
sudo ethtool -L enp12s0f0 combined 1
