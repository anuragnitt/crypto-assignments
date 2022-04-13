#include <iostream>
#include <random>

class SolvayStrassen
{
    private:
        int64_t jacobi(int64_t, int64_t);
        int64_t mod_exp(int64_t, int64_t, int64_t);
    
    public:
        bool is_prime(int64_t, int64_t);
};

int64_t SolvayStrassen::jacobi(int64_t a, int64_t b)
{
    if ((b <= 0) or (b % 2 == 0))
        return 0;

    int64_t jac = 1;

    if (a < 0)
    {
        a = -a;
        if (b % 4 == 3)
            jac = -jac;
    }

    while (a != 0)
    {
        while (a % 2 == 0)
        {
            a >>= 1;
            if (
                (b % 8 == 3) or
                (b % 8 == 5)
            ) jac = -jac;
        }

        std::swap(a, b);

        if (
            (a % 4 == 3) and
            (b % 4 == 3)
        ) jac = -jac;

        a = a % b;
    }

    if (b == 1)
        return jac;
    
    return 0;
}

int64_t SolvayStrassen::mod_exp(int64_t a, int64_t b, int64_t c)
{
    int64_t res = 1;

    while (b--)
    {
        res *= a;
        res %= c;
    }

    return res % c;
}

bool SolvayStrassen::is_prime(int64_t n, int64_t it)
{
    if (n < 2)
        return false;
    if (n == 2)
        return true;
    if (n % 2 == 0)
        return false;
    
    int64_t rand, a, jacobian, mod;
    std::random_device random;

    while (it--)
    {
        rand = abs(static_cast<int64_t>(random()));
        a = (rand % (n - 1)) + 1;
        jacobian = (n + this->jacobi(a, n)) % n;
        mod = this->mod_exp(a, (n - 1) >> 1, n);

        if (
            (jacobian == 0) or
            (mod != jacobian)
        ) return false;
    }

    return true;
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <number> <iterations>\n";
        return 1;
    }

    int64_t n = atoi(argv[1]);
    if (n < 0)
    {
        std::cerr << "<number> should be non-negative\n";
        return 1;
    }

    int64_t it = atoi(argv[2]);
    if (it <= 0)
    {
        std::cerr << "<iterations> should be positive\n";
        return 1;
    }

    SolvayStrassen().is_prime(n, it)
        ? std::cout << n << " is a prime number\n"
        : std::cout << n << " is not a prime number\n";
    
    return 0;
}
