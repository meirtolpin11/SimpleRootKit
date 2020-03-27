int main () {
 
        setreuid (1111, 1111);
        system ("/bin/sh");
 
        return 0;
}
