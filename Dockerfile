FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /worker ./cmd/worker

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /worker /worker
USER nonroot:nonroot
ENTRYPOINT ["/worker"]
