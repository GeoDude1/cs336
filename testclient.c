#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <json/json.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
int main()
{ 
    char* str;
    int fd = 0;
    struct sockaddr_in servaddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
    {
        printf("Error : Could not create socket\n");
        return 1;
    }
    else
    {
        // assign IP, PORT 
    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
    servaddr.sin_port = htons(PORT); 
    memset(servaddr.sin_zero, '\0', sizeof(servaddr.sin_zero));
    }

    if (connect(fd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
         printf("ERROR connecting to server\n");
         return 1;
    }

    /*Creating a json object*/
    json_object *jobj = json_object_new_object();

    struct json_object *parsed_json; //structure that holds parsed JSON
    //stores rest of fields of the JSON file
    struct json_object *Server_IP_Address;
    struct json_object *Source_Port_Number_UDP;
    struct json_object *Destination_Port_Number_TCP_Head;
    struct json_object *Destination_Port_Number_TCP_Tail;
    struct json_object *Port_Number_TCP;
    struct json_object *Size_UDP_Payload;
    struct json_object *Inter_Measurement_Time;
    struct json_object *Number_UDP_Packets;
    struct json_object *TTL_UDP_Packets;

    fp = fopen("myconfig.json","r"); //opens file
    fread(buffer, 1024, 1, fp); //reads files and puts contents inside buffer
    fclose(fp);

    parsed_json = json_tokener_parse(buffer); //parse json file's contents and convert them into a json object

    json_object_object_get_ex(parsed_json, "Server_IP_Address", &Server_IP_Address);
    json_object_object_get_ex(parsed_json, "Source_Port_Number_UDP", &Source_Port_Number_UDP);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Head", &Destination_Port_Number_TCP_Head);
    json_object_object_get_ex(parsed_json, "Destination_Port_Number_TCP_Tail", &Destination_Port_Number_TCP_Tail);
    json_object_object_get_ex(parsed_json, "Port_Number_TCP", &Port_Number_TCP);
    json_object_object_get_ex(parsed_json, "Size_UDP_Payload", &Size_UDP_Payload);
    json_object_object_get_ex(parsed_json, "Inter_Measurement_Time", &Inter_Measurement_Time);
    json_object_object_get_ex(parsed_json, "Number_UDP_Packets", &Number_UDP_Packets);
    json_object_object_get_ex(parsed_json, "TTL_UDP_Packets", &TTL_UDP_Packets);


    char temp_buff[MAX_SIZE];

    if (strcpy(temp_buff, json_object_to_json_string(jobj)) == NULL)
    {
        perror("strcpy");
        return EXIT_FAILURE;
    }

    if (write(fd, temp_buff, strlen(temp_buff)) == -1)
    {
        perror("write");
        return EXIT_FAILURE;
    }

    printf("Written data\n");
    return EXIT_SUCCESS;
}