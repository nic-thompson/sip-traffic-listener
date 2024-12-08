# Build stage
FROM node:20-alpine AS build

# Install necessary build tools and dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    libpcap-dev

# Set working directory
WORKDIR /home/node

# Copy dependency files and install dependencies
COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install

# Copy the application code and build it
COPY . .
RUN pnpm run build

# Production stage
FROM node:20-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache libpcap

# Set working directory
WORKDIR /home/node

# Copy the built application from the build stage
COPY --from=build /home/node .

# Start the application
CMD ["node", "./dist/src/index.js"]
