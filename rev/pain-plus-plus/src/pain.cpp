#include <exception>
#include <iostream>
#include <map>
#include <vector>


class exception_with_vector : public virtual std::exception {
        std::vector<int> vector;
    public:
        exception_with_vector(std::vector<int> vector) : vector(vector) {}
        virtual std::vector<int>& get_vector() {
            return vector;
        };
};


class exception_with_map : public virtual std::exception {
        std::map<char, int> map;
    public:
        exception_with_map(std::map<char, int> map) : map(map) {}
        virtual std::map<char, int>& get_map() {
            return map;
        };
};


class exception_with_both : public exception_with_vector, public exception_with_map {
    public:
        exception_with_both(std::vector<int> vector, std::map<char, int> map) : exception_with_vector(vector), exception_with_map(map) {}
};


class exception_with_string : public virtual std::exception {
    public:
        std::string string;
        exception_with_string(std::string string) : string(string) {}
        char const* what() const noexcept override {
            return string.c_str();
        }
};

int main() {
    std::cout << "Enter the flag: " << std::flush;
    std::string input;
    std::cin >> input;
    std::erase(input, '\n');
    try {
        try {
            // encode the flag into the vector
            std::vector<int> vector = {28, 7, 27, 12, 30, 20, 39, 33, 4, 28, 15, 31, 39, 33, 15, 4, 7, 25, 12, 15, 26, 39, 15, 26, 6, 31, 15, 26, 3, 12, 15, 20, 7, 18, 28, 39, 20, 5, 15, 2, 29, 7, 15, 18, 12, 35, 26, 15, 26, 7, 16, 12, 15, 13, 38, 14, 28, 1, 27, 19, 29, 27, 22, 2, 21, 10};
            std::map<int, char> map1 = {{29, 'b'}, {28, 'd'}, {16, 'm'}, {10, '}'}, {13, '6'}, {31, 'y'}, {30, '{'}, { 7, 'i'}, { 2, 'a'}, { 1, 'f'}, {22, '1'}, {26, 't'}, {19, '4'}, {37, 'q'}, { 9, '2'}, { 3, 'h'}, {36, 'j'}, {33, 'u'}, { 8, '3'}, {21, '0'}, {32, 'z'}, {38, '8'}, {24, 'v'}, {12, 'e'}, {35, 'x'}, { 6, 'r'}, {14, '5'}, {25, 'k'}, {15, '_'}, {20, 'w'}, {39, 'o'}, {17, '7'}, { 4, 'l'}, { 5, 's'}, {18, 'n'}, {27, 'c'}, {23, 'g'}, {11, 'p'}, {34, '9'}};
            std::map<char, int> map2;
            for(auto const& [key, value] : map1) {
                map2[value] = key;
            }
            throw exception_with_both(vector, map2);
        } catch (std::exception const& e) {
            try {
                auto ex = dynamic_cast<exception_with_both const&>(e);
                int i = 0;
                for(char c : input) {
                    if (ex.get_map()[c] != ex.get_vector()[i]) {
                        throw exception_with_string(std::string("wrong!"));
                    }
                    ++i;
                }
                if (i != ex.get_vector().size()) {
                    throw exception_with_string(std::string("wrong!"));
                }
                throw exception_with_string("correct!");
            } catch (std::bad_cast const& bad_cast_e) {
                std::cout << "internal error!";
                throw;
            }
        }
    } catch (std::exception const& e) {
        std::cout << e.what() << std::endl;
    }
}
