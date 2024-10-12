# SIP Traffic Interceptor
A Node.js-based application designed to capture and log SIP traffic (REGISTER, UNREGISTER) on the network using libpcap. This application is dockerized and built for deployment on Linux machines.
#### Build the Docker Image
```pnpm docker:build```

#### Export the Docker Image
Once the image is built, export it to a tar file for transfer (if needed).

```pnpm docker:export:interceptor```

#### Transfer the Docker Image
Use scp or similar to transfer the Docker image to the target Linux machine.

```scp interceptor_image.tar voco@<server-ip>:/home/vocovo/```

### The rest of the steps are on the Linux box

Stop the existing container if it exists
```sudo docker stop sip-traffic-interceptor```

Remove the existing container if it exists
```sudo docker rm sip-traffic-interceptor```

#### Load the Docker Image
On the target Linux machine, load the image into Docker.

```sudo docker load -i interceptor_image.tar```

#### Run the Container
Make sure to set the appropriate network interface (eth2 in this case) for the container to capture traffic.

```sudo docker run --privileged --network host --restart unless-stopped --name sip-traffic-interceptor -d sip-traffic-interceptor```

#### Verify the Container
You can verify that the container is running and capturing traffic by viewing the logs.

```sudo docker logs -f sip-traffic-interceptor```

### Configuration
Network Interface: Ensure that the correct network interface (e.g., eth2) is specified in the application.

SIP Port: The application captures SIP traffic on port 5060 by default. This can be modified in the source code if needed.
