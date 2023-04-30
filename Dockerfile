FROM node:18.15.0

WORKDIR /app

# RUN npm install -g yarn

COPY package.json .
RUN yarn install
COPY . .

CMD yarn start:dev