# Getting started
`pip install -r requirements.txt`

# Setting up Key Distribution Server
`python key_distribution_server.py`

# Setting Up Communication Nodes

## Bob
`python client.py --client_name bob --server_only`

--server_only indicates that bob will not seek to communicate with alice but is passively waiting

## Alice
`python client.py --client_name alice`

