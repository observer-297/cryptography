import math

# 主函数，计算最终的结果
def compute_final_sum():
    prime_p = 1009
    prime_q = 3643
    
    # 计算欧拉函数 φ(n) = (prime_p - 1) * (prime_q - 1)
    totient_n = (prime_p - 1) * (prime_q - 1)
    
    # 获取 prime_p 和 prime_q 对应的所有未隐藏消息数量
    unconcealed_count_p = calculate_unconcealed_for_all_exponents(prime_p)
    unconcealed_count_q = calculate_unconcealed_for_all_exponents(prime_q)

    # 找到 prime_p 和 prime_q 对应的最小未隐藏消息数量
    min_unconcealed_p = min(unconcealed_count_p)
    min_unconcealed_q = min(unconcealed_count_q)

    # 计算满足条件的所有 e 的总和
    total_sum = sum(exponent for exponent in range(totient_n)
                    if unconcealed_count_p[exponent % (prime_p - 1)] == min_unconcealed_p and
                    unconcealed_count_q[exponent % (prime_q - 1)] == min_unconcealed_q)
    
    return str(total_sum)


# 计算给定素数 prime 下所有可能的未隐藏消息数量
def calculate_unconcealed_for_all_exponents(prime):
    unconcealed_counts = []
    for exponent in range(prime - 1):
        # 只有当 exponent 与 (prime - 1) 互质时，才计算未隐藏消息数量
        if math.gcd(exponent, prime - 1) == 1:
            unconcealed_counts.append(count_unconcealed_messages(prime, exponent))
        else:
            unconcealed_counts.append(10**20) 
    return unconcealed_counts


# 计算给定模数 modulus 和指数 exponent 的未隐藏消息数量
def count_unconcealed_messages(modulus, exponent):
    unconcealed_message_count = 0
    for message in range(modulus):
        # 如果 message^exponent ≡ message (mod modulus)，则 message 是未隐藏的
        if pow(message, exponent, modulus) == message:
            unconcealed_message_count += 1
    return unconcealed_message_count


if __name__ == "__main__":
    print(compute_final_sum())