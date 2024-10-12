FROM node:20-alpine AS build

RUN apk add --no-cache make g++ python3 libpcap-dev 

WORKDIR /home/node

COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile

COPY . .

RUN pnpm run build

FROM node:20-alpine AS production

RUN apk add --no-cache python3 make g++ libpcap-dev

WORKDIR /home/node

COPY package.json pnpm-lock.yaml ./
RUN npm install -g pnpm && pnpm install --frozen-lockfile --prod

COPY --from=build /home/node/dist ./dist

CMD ["node", "./dist/src/index.js"]
