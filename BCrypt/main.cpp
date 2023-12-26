// BCrypt.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "read_file.h"

int main()
{
    std::string file_path;
    std::string key;
    std::string choice;

    printf_s("Do you wish to (E)ncrypt or (D)ecrypt a file?\n");
    std::cin >> choice;

    if (choice == "e" || choice == "E")
    {
        printf_s("Insert the path to the file to encrypt: ");
        std::cin >> file_path;

        printf_s("Insert a 16-character key to encrypt the file: ");
        std::cin >> key;

        _ReadFile file{ file_path, key };
        file.LoadData();
        file.Encrypt();

    }
    else if (choice == "d" || choice == "D")
    {
        printf_s("Insert the path to the file to decrypt: ");
        std::cin >> file_path;

        printf_s("Insert a 16-character key to decrypt the file: ");
        std::cin >> key;

        _ReadFile file{ file_path, key };
        file.LoadData();
        file.Decrypt();
    }
    else
    {
        printf_s("Your choice isn't valid\n");
    }
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
