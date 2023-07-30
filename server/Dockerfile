FROM node:16.20.0

WORKDIR /app

COPY package*.json ./

RUN npm install 

COPY . . 

EXPOSE 8000

# Use script specified in package,json
CMD ["npm", "start"]
