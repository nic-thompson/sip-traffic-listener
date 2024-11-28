# Build stage
FROM node:20-alpine AS build

# Install necessary build tools and dependencies using apk (Alpine's package manager)
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    libpcap-dev

WORKDIR /home/node

# Copy package files and install dependencies
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install

# Copy the rest of the source code
COPY . .

# Build the application
RUN pnpm run build

# Production stage
FROM node:20-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache \
    libpcap

WORKDIR /home/node

# Copy built application from the build stage
COPY --from=build /home/node .

# Start the application
CMD ["node", "./dist/src/index.js"]
