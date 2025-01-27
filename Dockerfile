# mockin Dockerfile
FROM node:22-alpine
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --only=production
COPY ./src ./src
# default mockin port
EXPOSE 3333
# docker + node means IP to be 0.0.0.0 but exposed on host as 127.0.0.1
ENV IP=0.0.0.0
ENV ISSUER=http://127.0.0.1:3333
CMD ["npm", "start"]
