TARGET=test1main
OBJS=log.o test1main.o 

INC_PATH=./
%.o:%.cpp
	g++ -Wall -c $< $(INC_PATH) 

$(TARGET):$(OBJS)
	g++ -Wall -g $^ -ldl -L$(INC_PATH) -o $@
	cp -f $(TARGET) ../../output/bin

clean:
	rm -f *.o
	rm -f $(TARGET)
	
