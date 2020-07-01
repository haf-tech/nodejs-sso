FROM node:12-alpine

# Create node_modules which is needed for npm install and ensure right permission
RUN mkdir -p /home/node/app/node_modules && chown -R node:node /home/node/app

WORKDIR /home/node/app

COPY package*.json ./

USER node

RUN npm install

# Copy all relevant files
COPY --chown=node:node . .

ENV NODE_ENV production
ENV PORT 8080
EXPOSE 8080

CMD [ "npm", "start" ]
