
if __name__ == '__main__':
    nodes = [{'name': 'fake_name1', 'ip': 'node_ip1'},
             {'name': 'fake_name2', 'ip': 'node_ip2'},
             {'name': 'fake_name3', 'ip': 'node_ip3'}]

    a = [cluster_node['name'] for cluster_node in nodes]
    print a

    b =','.join(a)
    print b
    c = '123456789'.zfill(8)
    print c
    d ='test'
    e =[d]*3
    print e
