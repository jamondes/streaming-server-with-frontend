# Start from the official node image for the app build
FROM node:14.17.3

# Set working directory
WORKDIR /app

# add `/app/node_modules/.bin` to $PATH
ENV PATH /app/node_modules/.bin:$PATH

# Copy package files and install dependencies
COPY package.json ./
COPY package-lock.json ./
RUN npm install --silent

# Copy all source files
COPY . ./

# Start the app
CMD ["npm", "start"]