from config import ENABLE_LOGGING
import logging

def print_b(B):
    if ENABLE_LOGGING:

        print("B_0 = ", B)


def print_array(A, identifier):
    if ENABLE_LOGGING:
        if A:
            result = identifier + " = ["
            for i in range(0, len(A) - 1):
                result += " " + str(A[i]) + ","
            result += " " + str(A[len(A) - 1]) + " ]"
            print(result)


def print_round(round_number):
    if ENABLE_LOGGING:
        print("\n\nRound " + str(round_number) + ":")


def print_sides(A, B):
    if ENABLE_LOGGING:
        print("L -> ", str(A), "\nR -> ", str(B))