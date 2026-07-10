FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go vet ./... && CGO_ENABLED=0 go test ./...
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/access ./cmd/access

FROM scratch
COPY --from=build /out/access /access
USER 1000:1000
EXPOSE 8080
ENTRYPOINT ["/access"]
