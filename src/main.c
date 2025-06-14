#define _GNU_SOURCE

#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MAX_REQUEST_SIZE 4096
#define TIMEOUT 5

typedef struct request_headers {
  char *HOST;
  char *USER_AGENT;
  char *ACCEPT;
  char *ACCEPT_LANGUAGE;
  char *ACCEPT_ENCODING;
  char *REFERER;
  char *CONNECTION;
  char *UPGRADE_INSECURE_REQUESTS;
  char *IF_MODIFIED_SINCE;
  char *IF_NONE_MATCH;
  char *CACHE_CONTROL;
} request_headers;

int read_request(char buffer[], int client_fd, int server_fd);
char *extract_path(const char *input);
char *extract_headers(char *input, char *header, request_headers *request_header);

int main() {
  request_headers request_headers = {0};

  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  printf("Logs from your program will appear here!\n");

  int server_fd, client_addr_len;
  struct sockaddr_in client_addr;

  server_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (server_fd == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting SO_REUSEADDR
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEADDR failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(4221),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  int connection_backlog = 5;
  if (listen(server_fd, connection_backlog) != 0) {
    printf("Listen failed: %s \n", strerror(errno));
    return 1;
  }

  printf("Waiting for a client to connect...\n");
  client_addr_len = sizeof(client_addr);

  int client_fd =
      accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
  printf("Client connected\n");
  printf("Client_fd: %d\n", client_fd);
  if (client_fd < 0) {
    printf("Accept failed: %s \n", strerror(errno));
    return 1;
  }

  char request_buffer[MAX_REQUEST_SIZE];

  if (read_request(request_buffer, client_fd, server_fd) < 0) {
    printf("Failed to read request\n");
    close(client_fd);
    close(server_fd);
    return 1;
  }
  printf("Received request:\n%s", request_buffer);

  char *response = "\0";
  char *path = extract_path(request_buffer);
  printf("Path: %s\n", path);
  if (path == NULL || strcmp(path, "") == 0) {
    // Send 200 OK response
    response = "HTTP/1.1 200 OK\r\n\r\n";
    ssize_t bytes_sent = send(client_fd, response, strlen(response), 0);
  } else if (strncmp(path, "echo/", 5) == 0) {
    printf("len: %zu\n", strlen(path) - 5);
    asprintf(&response,
             "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
             "%li\r\n\r\n%s",
             strlen(path) - 5, path + 5);
    ssize_t bytes_sent = send(client_fd, response, strlen(response), 0);
  } else if (strcmp(path, "user-agent") == 0) {
    asprintf(&response,
             "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
             "%li\r\n\r\n%s",
             strlen(path) - 10, extract_headers(request_buffer, "User-Agent", &request_headers));
  } else {
    response = "HTTP/1.1 404 Not Found\r\n\r\n";
    ssize_t bytes_sent = send(client_fd, response, strlen(response), 0);
  }

  close(server_fd);
  close(client_fd);

  return 0;
}

int read_request(char buffer[], int client_fd, int server_fd) {
  int total_read = 0;
  buffer[0] = '\0';  // Initialize buffer to an empty string

  while (total_read <= MAX_REQUEST_SIZE - 1) {
    fd_set read_fds;
    struct timeval timeout;

    FD_ZERO(&read_fds);
    FD_SET(client_fd, &read_fds);

    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;

    int indication = select(client_fd + 1, &read_fds, NULL, NULL, &timeout);
    // printf("Indication from select: %d\n", indication);
    if (indication == -1) {
      printf("Select failed: %s\n", strerror(errno));
      close(client_fd);
      close(server_fd);
      return -1;
    } else if (indication == 0) {
      printf("Timeout occurred, no data received within %d seconds.\n",
             TIMEOUT);
      close(client_fd);
      close(server_fd);
      return -2;
    }

    ssize_t bytes_recvd = recv(client_fd, buffer + total_read,
                               MAX_REQUEST_SIZE - 1 - total_read, 0);
    if (bytes_recvd < 0) {
      printf("Receive failed: %s \n", strerror(errno));
      close(client_fd);
      close(server_fd);
      return -3;
    }

    total_read += bytes_recvd;
    buffer[total_read] = '\0';

    if (strstr(buffer, "\r\n\r\n")) {
      break;
    }

    if (total_read >= MAX_REQUEST_SIZE - 1) {
      printf("Request too large, exceeding maximum size of %d bytes.\n",
             MAX_REQUEST_SIZE);
      // Send 413 status code
      close(client_fd);
      close(server_fd);
      return -4;
    }
  }

  return total_read;
}

char *extract_path(const char *input) {
  regex_t regex;
  regmatch_t pmatch[2];
  const char *pattern = "^GET /([^[:space:]]*)";
  char *result = NULL;

  if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
    printf("Could not compile regex\n");
    return NULL;  // regex failed to compile
  }

  if (regexec(&regex, input, 2, pmatch, 0) == 0) {
    int start = pmatch[1].rm_so;
    int end = pmatch[1].rm_eo;
    int len = end - start;

    // If there's nothing after the slash, return empty string
    if (len == 0) {
      regfree(&regex);
      return "";
    }

    // Allocate memory (+1 for null terminator)
    result = malloc(len + 1);
    if (result == NULL) {
      perror("malloc failed");
      exit(1);
    }

    // Copy and null-terminate
    strncpy(result, input + start, len);
    result[len] = '\0';
  }

  regfree(&regex);
  return result;
}

char *extract_headers(char *input, char *header, request_headers *headers) {
  char *input_dup = strdup(input);
  if (input_dup == NULL) {
    return NULL;
  }

  char *saveptr;
  char *cur_line = strtok_r(input_dup, "\r\n", &saveptr);
  while (cur_line != NULL) {
    char *colon = strchr(cur_line, ':');
    if (colon) {
      *colon = '\0'; // Split the header name and value
      char *header_name = cur_line;
      char *header_value_start = colon + 1; // Moves past the colon

      while (*header_value_start == ' ' || *header_value_start == '\t') {
        header_value_start++; // Loop to skip leading spaces or tabs
      }

      char* header_value = strdup(header_value_start);
      if (header_value == NULL) {
        fprintf(stderr, "Warning: Failed to allocate memory for header '%s'\n", header_name);
        cur_line = strtok_r(NULL, "\r\n", &saveptr);
        continue;
      }

      if (strcasecmp(header_name, "User-Agent") == 0) {
        headers->USER_AGENT = header_value; // Store the header value
      }
    }
  }
  
  free(input_dup);
  return NULL;
}