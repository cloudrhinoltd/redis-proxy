# Copyright (C) 2024 Cloud Rhino Pty Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This Dockerfile contains parts under a dual-license:
# Only the 'enable_protocol_attack' and 'enable_general_rules' features are 
# covered by the Apache 2.0 License, other features require a commercial license.
#
# GitHub Repo: https://github.com/cloudrhinoltd/ngx-waf-protect
# Contact Email: cloudrhinoltd@gmail.com

# # Use the official Golang image to create a build artifact.
FROM golang:1.22.1 as builder

# # Set the working directory inside the container
WORKDIR /app

# # Copy go mod and sum files along with the vendor directory
COPY go.mod go.sum ./

# # Copy the source code
COPY *.go ./

RUN go mod tidy

# # Build the Go app using the vendor directory
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# # Use a minimal alpine image for the final build
FROM alpine:3.14 

# Set the working directory inside the container
WORKDIR /root/

# Copy the pre-built binary file from the builder stage
COPY --from=builder /app/main .

# Expose port 6379
EXPOSE 6379

# Run the executable
CMD ["./main"]
