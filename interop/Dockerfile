FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json ./
COPY lib ./lib
COPY examples ./examples
COPY interop ./interop
ENV NODE_ENV=production
CMD ["node","interop/endpoint.js"]