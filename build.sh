#!/bin/bash
set -e

echo "Building frontend..."
cd frontend
npm install
npm run build
cd ..

echo "Building backend..."
go build -o url-shortener

echo "Build complete! Run ./url-shortener to start the server."
