FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/veto-gateway .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/veto-gateway /veto-gateway
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/veto-gateway"]
