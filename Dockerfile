# mockin Dockerfile
FROM node:18-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production
COPY ./src ./src
EXPOSE 3333
CMD ["node", "./src/server.js"]
