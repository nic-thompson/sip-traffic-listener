FROM node:20-slim AS build

# Use apt-get instead of apk to install the necessary packages
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/node

# Copy package files and install dependencies
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install

# Copy the rest of the source code
COPY . .

RUN pnpm run build

# Production stage
FROM node:20-slim AS production

# Install production dependencies using apt-get
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /home/node

COPY --from=build /home/node .

CMD ["node", "./dist/src/index.js"]
