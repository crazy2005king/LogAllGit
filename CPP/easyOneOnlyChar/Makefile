TARGET=test1main
OBJS=log.o test1main.o 

%.o:%.cpp
	g++ -Wall -c $< 

$(TARGET):$(OBJS)
	g++ -Wall -g $^ -ldl -o $@
	cp -f $(TARGET) ../output/dll

clean:
	rm -f *.o
	rm -f $(TARGET)
	
