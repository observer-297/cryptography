def euler_problem_182():
    p = 1009
    q = 3643
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    min_unconcealed = float('inf')
    valid_es = []

    for e in range(2, phi_n):
        if gcd(e, phi_n) == 1:
            unconcealed_count = count_unconcealed_messages(e, n)
            if unconcealed_count == min_unconcealed:
                valid_es.append(e)
            elif unconcealed_count < min_unconcealed:
                min_unconcealed = unconcealed_count
                valid_es = [e]
    
    return sum(valid_es)

def count_unconcealed_messages(e, n):
    return sum(1 for m in range(n) if pow(m, e, n) == m)