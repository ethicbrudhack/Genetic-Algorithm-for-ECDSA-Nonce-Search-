#!/usr/bin/env python3
import random
import math
from deap import base, creator, tools, algorithms
from functools import lru_cache
import ecdsa
from ecdsa.numbertheory import inverse_mod

# Parametr grupy ECDSA (secp256k1)
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Przykładowe dane podpisów dla badanego adresu – uzupełnij poniższe dane
# Każdy podpis musi zawierać wartości r, s oraz z jako liczby całkowite.
signatures = [
  {
        "r": int("27c90531406bbf08bd6325b06fe0ac32e61a66f3d8b2762a7bf2ac6c13e76ddc", 16),
        "s": int("096ddba45472fe9cca48753e7ca89b70ef358badbd458e08ef77fc79a85d7ae8", 16),
        "z": int("af35ac2dfa66a276070a9876c1108a53744b8c1f0d2a339443e93c4f892dd82", 16)
    },
    {
        "r": int("ab9467e44699c0ab5ee2da6389e1646725a03bd66433eb99e531e45d76476ee0", 16),
        "s": int("59098b9fe30776049508f91eea10e4a9972eec2c1afe79674379578447b7aa46", 16),
        "z": int("726c33406e9d8ac5824b9ab64a252c27146c26907b23eb082ac72b324c2e1167", 16)
    },
    {
        "r": int("d8e2d92d3fca2a3293ed2e57c80a8db40069da2229225756b77de2f967baa1fb", 16),
        "s": int("6f2dc5ce39475b4c98ae27285a36939aadf19e38b3845c57400ef08326d24d23", 16),
        "z": int("d1a2c75e09ff62d7fb23ca60ce8c28b14f05684595e5ff2f87bad3c01eae1240", 16)
    },
    {
        "r": int("ba4cbf9de2d8f8cec6ace7fd8fde68b6bb247a3494618f0684a07542557d8dd1", 16),
        "s": int("6a8dd246334494bbb852c19e885af8b951e90983438cd6eef7daf01ba2a21453", 16),
        "z": int("a23b101ec31f5a989e94da96df416463cfc580b63c43d994da6c7a56adfe9355", 16)
    },
    {
        "r": int("dc6908cb781b1276ef6b99d8b0db18f7c8a5537aa4eaa914882360f018ac2229", 16),
        "s": int("5e0c89a881636fd9c4b454d1958a6b8b4d91cac66605eece3f884bacc9699a6d", 16),
        "z": int("ba75fa9df7667dbfe6491a7a4f92efe585ad905ad80bdce2db26047c943c6efe", 16)
    },
    {
        "r": int("456f2b274a1fa5ab41d2e3ecbd784e562b698802c4e3edd87fd612d0574b63c1", 16),
        "s": int("38b9d6b3bbb576bea89e848d7fad0119ad536cf6805f19922ad8f0bb154af0e8", 16),
        "z": int("36dea578c35a7488527f63e28abd98097057a1a7c2bcccc7223079b73e6f6a47", 16)
    },
    {
        "r": int("059e1d87695c9ccaade2870853f77d6f540cbf3e5f7c6dd3e9d024ccf61ef376", 16),
        "s": int("78060a2b523d37eae1a25f356cf01d28e9b5e0375f524596ef0344d2a9107eed", 16),
        "z": int("1888b57b470d7b17539213aa675bdd31ae5c7a8eb0f1948f4cf01c91f11edd7b", 16)
    },
    {
        "r": int("208adbce62f52987c4e2e8f49ee18f2176bb699e7f8d0bd10f5b9ef8a9acd045", 16),
        "s": int("41b2da4a50944ec64be0975b06ae56292a1aad235a09acea8904bee4869630bb", 16),
        "z": int("33a145a867d29628e2178ba57d682220079b758a52152e007c47687b02d4fd43", 16)
    },
    {
        "r": int("f676052e29ab14b5ea8a4515696edb2732ae765b4aee763e16a208e9f7753178", 16),
        "s": int("1ee030b36dba2a21fe236512668af824dcbb382a7a8aa962b3792ca6dc6a5efe", 16),
        "z": int("7d5a9d992a12716f248751b31a34d8c12ffcad27563a6f09da8fabb078299fd9", 16)
    },
    {
        "r": int("660d24f06ae101318e77799e08f4dc111dd914618ad0be347b558f5d7520c294", 16),
        "s": int("10a00a5f9fcb6e4867b5f4145cd4735503d94d5f0f9c7a1398a5612e92950c65", 16),
        "z": int("d4eb33937bc83e47c601f57ef982b7ffc7c8889fe4f6afdecf199b5583fe2daf", 16)
    },
    {
        "r": int("f20b8c96e8f302898853acf7c5a5e892c1fab211031677b501e02f60d6ca803e", 16),
        "s": int("01b84106f4b7cafce16ed3490d24049079e1be59aaa9247d3ca66bcc4b493072", 16),
        "z": int("eb908a5a7d23a3ce7e6c3a22477dfaa3e3f455b48488b12e84ccba6228067e5d", 16)
    },
    {
        "r": int("a674f3ced3e25621cde299d20a700ccab080eb8352db313c5e039473ae48df83", 16),
        "s": int("57d8156cb1f7d1b390a13bc008bb3f2478d5552d00cc75215f21bbef866bec55", 16),
        "z": int("c7c58a952ca7b31ced67bfea57fd7571314f8d77a88c90f42e68bdd82c2adb4f", 16)
    },
    {
        "r": int("ea5de69f993b8d45df047375c024ee1de15d0e74ce724d620d9cb8af0a33b6b", 16),
        "s": int("09489be3c7507a53d0e9d2a2fc218bea2fe3515e57d6abf67c97ba1541a21bbf", 16),
        "z": int("a5c810feecdabef9dfdc0e348d7802c980592cc2d7155969338e78fab1b5f515", 16)
    },
    {
        "r": int("f6c4e452854173e522b7d30d0072eb162101367e23f00956ad9c63c00baef6d5", 16),
        "s": int("246bdd9b1f92067713b9566d7a6bafa2ba43d4f5f07ec3f0bef8e6de78d39cd8", 16),
        "z": int("b67496bf70694a89c13aa57777abd000caac00115247b3a3e4a985e37d2a41a5", 16)
    },
    {
        "r": int("3cddff9fa3e896a4a75c8534102295317cfa3679e4775f6eb110e0a20aaf25bf", 16),
        "s": int("4aa414e556db0f1b81fc34f147e95bc45fa674edfe6dd38502934ada23ec548d", 16),
        "z": int("ad49188901c858be114bcf91bd41f62460037c46d0486b1590f3f3e85ef3a6aa", 16)
    },
    {
        "r": int("a7fe3bb203380e9510f9978902347fa8ca3df977a4d72761b2265834de613516", 16),
        "s": int("2a6a23cb1ecf11bbac499093081372c58d8b83f4451d6947dfd4d1132735a779", 16),
        "z": int("3357929b3da196ad20320ea170447e7470e7d6f91e0213fea4c3231961b791f0", 16)
    },
    {
        "r": int("916ff5faa2f5fd40db2ea8972b1edfe6a63f13e2294c6e5cbd86149b4066e0ba", 16),
        "s": int("294fd52259ec8864788f0218927d00ac8e1d6b5380da5ea520745899e860ceaa", 16),
        "z": int("db9237f82094111d25f5e928c63a13236bb3ea2359ea085c8f12fac26876ae5b", 16)
    },
    {
        "r": int("70908443446bb7d2ea17f957a7988cbfaa0cf7072812e9290ea602061999efac", 16),
        "s": int("46f5afb7acd91e97ae6776c25b5592de8f287105e8b83ab71456c03a62c64bf2", 16),
        "z": int("5b070d63f06c47fd0ad66d006e3b4671a4dd5c2c971f0546458fed45fc7cd244", 16)
    },
    {
        "r": int("ac2a02121824dac496f3579e06538339b0d195e72f7bd3ca43865825df9b5920", 16),
        "s": int("7c90e85461651eeef17cfb57aa0d881360b5958e6b16922d3042695303838312", 16),
        "z": int("6203853062604290bb8761bff05c4e8d5466dc7537f2b5949554d3062e2db1ac", 16)
    },
    {
        "r": int("8987849abc2b94ada430425e33ec95336c659c59e1a039b7c5581ce45b6326a3", 16),
        "s": int("4ea8f8ea05d52dea91be0fe4bfbcd3f15d7795d41382eaece6e1ebd13e8d963a", 16),
        "z": int("c7a8099c3cfe851c00134f1273dd5d55035cb66b829752513bc03a63a023ae00", 16)
    },
    {
        "r": int("64669b93916da2479cf05d1afb934e6ba1f8a5d075653d78ffda73aea58f0dc7", 16),
        "s": int("165cce6cbd3319962ad293274ded1c55f32ce1140f21de151f374cac43c14867", 16),
        "z": int("a670e721c7897165cefcac80c39156a7631883c0fbf06cdf3f6a88001895b1e3", 16)
    },
    {
        "r": int("4122285f136a320f7c703b3e426c59238918d9109e7c3941fc6a0b6adf5207f7", 16),
        "s": int("1e93eb84918f74f5a26d32366907af8c6ab9e1942b9efb6d935dbe178d06e9ff", 16),
        "z": int("c1883c33976b004419d5acc5c449fa94abfc2deb76280a5b7cea1ec5bd93db59", 16)
    },
    {
        "r": int("d49081dbc8456347d95a13f012f952ba515c3a2d7e6a217a45d524231f9e73be", 16),
        "s": int("129b6d94862d072a25c381264f280ed4a72d6a6e72d14971d0d7be4339c91893", 16),
        "z": int("e87013260748173d6f9926318e836a4e4d613875999ea1cd3449365644274ea8", 16)
    },
    {
        "r": int("d586bc4612c60c1c7720d7abe39ab1495f85741b1c307973064732c72ed00216", 16),
        "s": int("56bf08497eefcec00fac3a304d3ddcc0c7555a278834ed62cc5f40459842959a", 16),
        "z": int("4ce442afa7e129f8770706df916ce95f939ebd2e2c593909de158075b72fa381", 16)
    },
    {
        "r": int("bde208ab14f08c144c476ad0913b819ac85edb0817648f7a9c7bfba6ff3d2ae4", 16),
        "s": int("361cd7453471392f166f75fae077c6eab3bb87b3cf097e6c8e821b647adfa2c8", 16),
        "z": int("88eb119a2cb92c5d40cb5418c5835e82092fb7053f3ab885653d817b40597d49", 16)
    },
    {
        "r": int("5ebecec888b158797ded9ebc1421b4797d4077c2e16945f45361ac33f6abf41b", 16),
        "s": int("340050758fd9de606d45383f63f1b236a7a47318c595e99c910f4b943a88a364", 16),
        "z": int("6a880556287111baf49b95e61e193885db6882bf696f00f1efb6456b6ac4c521", 16)
    },
    {
        "r": int("d3ba3cab814f547073ee20c4aa7359727bc1ab8f21f05482e0c1dc9b49a0291a", 16),
        "s": int("4c66a7756c7515031c29984cc679fc2d4f19774056b8b31d9d7acac9e74483a4", 16),
        "z": int("708c19095fb11344056860ea50202058f8c737bbfe5cc224de42cd450ae4666e", 16)
    },
    {
        "r": int("1d999473385022d0090415d261ade01bf9a114def08067c51e4bd4817b1b570f", 16),
        "s": int("6a87e0ac7a5b2e7cb6d9716ae639080ad667642e1b2fbbf323dbe9a75481b163", 16),
        "z": int("2882e52b5b6f0e95b05657aa2bff57032f365272f2c8c28e0188eccdeb72e49e", 16)
    },
    {
        "r": int("b58fa95ed13ac33554af3ed51374a9e72e5410754184c906c5b1dc1f6cca9e76", 16),
        "s": int("190a53c0948efdae5a563e851eb143e250a173cddc86a90edc5446bb3b084eb2", 16),
        "z": int("5929aa4e1752814f794b1152fe97268bf7ab4135c7fd7b8c0e97c2db3409a954", 16)
    },
    {
        "r": int("c5e1f90d0d2c0aec92f5d60a99ad2811c738364dbce8304b6e7ec6a0f5df257a", 16),
        "s": int("06b2d214a7422bf524bff6c08bf39308604d3f09d912e6aa2efea4b0a681e60c", 16),
        "z": int("fa72464e5996133c440a77a3de47a081d93f02f9aa0f28a82de3c6a5cac81569", 16)
    },
    {
        "r": int("2c56535aaceb9dd2e39fa63a44eb352e748d411bae598c84509c0b5b294ca1b8", 16),
        "s": int("5e13205678e60cfa8d85b0f9c65a26d71f9f7d605dd9be352ce5e2cf76d70c4a", 16),
        "z": int("d0640eabf26fdc8644273b4dc998564fdd10cf030376d4cab94a3cc63d7473be", 16)
    },
    {
        "r": int("b598a96eba7b6c446c9952dadaf4fe47cc8790fcb4fe213f057ee164ca6d6d27", 16),
        "s": int("7c6713418c03c04a4fe1706152689d8af771d750f774d651d01ddc156fc66350", 16),
        "z": int("46c4be378255864cff78f55319526dd6efccfa2c43d9166f428ebfb092a7aae2", 16)
    },
    {
        "r": int("983e234fc4998fa10495e28ffd9dc874ee1d9792b82fb196b7caae53cc9a7dc7", 16),
        "s": int("0e09c0b0fe6650c709d8cd0bbf57a8682416c3c947c5026a75656fa64ab22db9", 16),
        "z": int("9eb094e4f1f870e246d5405558bdb22dfea7bf91d49d01c9bb55d66026464df7", 16)
    }
]

# Funkcja odzyskująca d dla danego podpisu i k
@lru_cache(maxsize=None)
def recover_d(r, s, z, k):
    try:
        inv_r = inverse_mod(r, n)
    except Exception:
        return None
    d = ((s * k - z) % n) * inv_r % n
    # Klucz powinien być z zakresu (1, n)
    if 1 < d < n:
        return d
    return None

# Funkcja celu dla optymalizacji:
# Dla danego k obliczamy d dla każdego podpisu i sumujemy różnice między kolejnymi d.
def objective(k, signatures):
    k = int(k % n)
    ds = []
    for sig in signatures:
        d_val = recover_d(sig["r"], sig["s"], sig["z"], k)
        if d_val is None:
            ds.append(n)  # kara – duża wartość, jeśli nie uda się odzyskać d
        else:
            ds.append(d_val)
    error = 0
    for i in range(len(ds)):
        for j in range(i + 1, len(ds)):
            error += abs(ds[i] - ds[j])
    return error, ds

# Ustawienia algorytmu genetycznego przy użyciu DEAP
creator.create("FitnessMin", base.Fitness, weights=(-1.0,))
creator.create("Individual", list, fitness=creator.FitnessMin)

toolbox = base.Toolbox()
# Losujemy k z zakresu [1, n-1]
toolbox.register("attr_int", random.randint, 1, n - 1)
toolbox.register("individual", tools.initRepeat, creator.Individual, toolbox.attr_int, 1)
toolbox.register("population", tools.initRepeat, list, toolbox.individual)

def eval_individual(individual):
    k_candidate = individual[0]
    error, ds = objective(k_candidate, signatures)
    return (error,)

toolbox.register("evaluate", eval_individual)
toolbox.register("mate", tools.cxUniform, indpb=0.5)
# Modyfikujemy wartość k przy użyciu mutacji gaussowskiej
toolbox.register("mutate", tools.mutGaussian, mu=0, sigma=n // 1000, indpb=0.2)
toolbox.register("select", tools.selTournament, tournsize=3)

def main():
    random.seed(42)
    population = toolbox.population(n=50)
    NGEN = 100  # liczba generacji – zwiększ w razie potrzeby
    best_individual = None
    for gen in range(NGEN):
        offspring = algorithms.varAnd(population, toolbox, cxpb=0.5, mutpb=0.2)
        fitnesses = list(map(toolbox.evaluate, offspring))
        for ind, fit in zip(offspring, fitnesses):
            ind.fitness.values = fit
        population = toolbox.select(offspring, k=len(population))
        best_individual = tools.selBest(population, 1)[0]
        best_error, best_ds = objective(best_individual[0], signatures)
        print(f"Generacja {gen}: najlepsze k = {best_individual[0]} z błędem = {best_error}")
        # Opcjonalnie: zakończ, gdy błąd jest bardzo niski (np. < 100)
        if best_error < 100:
            break

    final_k = best_individual[0]
    final_error, final_ds = objective(final_k, signatures)
    print("\nNajlepszy kandydat:")
    print(f"k = {final_k}")
    print(f"Błąd = {final_error}")
    if final_ds:
        candidate_d = final_ds[0]
        print(f"Szacowany klucz prywatny d = {candidate_d}")
    else:
        print("Nie udało się odzyskać wartości d dla żadnego podpisu.")

if __name__ == "__main__":
    main()
