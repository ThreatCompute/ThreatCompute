import math
import cvss
import math
from dataclasses import dataclass
from decimal import Decimal as D


@dataclass
class Score:
    base: float
    esc: float


class KUBE_TTC:
    def __init__(self, cvss_scores, misconfigurations=[], m_s=None):
        self.c1 = 1  # time to tune an exploit (in days)
        self.c3 = 10.14  # time to find a new vulnerability (in days)
        self.k = 270139  # total number of known vulnerabilities (based on NVD)
        self.scores = []
        self.avg_exploitability = 5
        self.max_exploitability = 5
        if cvss_scores or misconfigurations:
            self.preprocess_scores(cvss_scores, misconfigurations)
        self.v = len(self.scores)
        # Assign m to the provided m_s if it exists, else use the default
        if m_s:
            self.m = m_s  # Override the method with the provided version
        else:
            self.m = self.default_m  # Use the default version of m

    def preprocess_scores(self, cvss_scores, misconfigurations):
        """
        Preprocess the CVSS scores and misconfigurations to be used in the TTC calculation

        Args:
            cvss_score (float): Version 2 and Version 3.1 CVSS scores
            misconfigurations (list): List of misconfigurations with a scoreFactor
        """
        scores = []
        for cvss_score in cvss_scores:
            if isinstance(cvss_score, cvss.CVSS3):
                exploitability_score = (
                    D("20")
                    * cvss_score.get_value("AV")
                    * cvss_score.get_value("AC")
                    * cvss_score.get_value("PR")
                    * cvss_score.get_value("UI")
                )
                scores.append(Score(cvss_score.base_score, exploitability_score))
            elif isinstance(cvss_score, cvss.CVSS2):
                exploitability_score = (
                    D("20")
                    * cvss_score.get_value("AV")
                    * cvss_score.get_value("AC")
                    * cvss_score.get_value("Au")
                )
                scores.append(Score(cvss_score.base_score, exploitability_score))

        for control in misconfigurations:
            scores.append(Score(control["scoreFactor"], control["scoreFactor"]))

        self.scores = scores

        self.avg_exploitability = sum([score.esc for score in self.scores]) / len(
            self.scores
        )
        self.max_exploitability = max([score.esc for score in self.scores])

    def default_m(self, s):
        if s == "novice":
            return 2418
        elif s == "beginner":
            return 3220
        elif s == "intermediate":
            return 4956
        else:
            # s == 'expert'
            return 5800

    def c2(self, s):
        """
        Time to develop a new exploit per attacker skill level
        """
        if s == "novice":
            return 30.4
        elif s == "beginner":
            return 20.6
        elif s == "intermediate":
            return 10.8
        else:
            # s == 'expert'
            return 1

    def f(self, s):
        if s == "novice":
            return 0.05
        elif s == "beginner":
            return 0.24
        elif s == "intermediate":
            return 0.5
        else:
            # s == 'expert'
            return 1

    def x(self, s):
        if s == "novice":
            return 7.3
        elif s == "beginner":
            return 5.5
        elif s == "intermediate":
            return 2.9
        else:
            # s == 'expert'
            return 0.3

    def calc_P1(self, s):
        base_score_factor = float(sum([score.base for score in self.scores]) / 10)
        return 1 - math.exp(-base_score_factor * (self.m(s) / self.k))

    def calc_u(self, s):
        """
        Calculate u, the probability that process 2 is not successful
        """
        if self.v == 0:
            return 1
        exploitable_vulnerabilities = len(
            [score for score in self.scores if score.esc > self.x(s)]
        )
        u = (1 - (exploitable_vulnerabilities / self.v)) ** self.v
        u_min_max_rounded = min(max(u, 0.05), 0.95)
        return u_min_max_rounded

    def calc_t1(self):
        """
        Calculate t1, the time to tune an exploit
        """
        return float(self.c1 * 10 / self.max_exploitability)

    def calc_t2(self, s):
        """
        Calculate t2, the time to develop a new exploit
        """
        return float(self.c2(s) * 10 / self.max_exploitability)

    def calc_process1(self, s):
        """
        Calculate the probability that process 1 is successful
        """
        return self.calc_t1() * self.calc_P1(s)

    def calc_process2(self, s):
        """
        Calculate the probability that process 2 is successful
        """
        return self.calc_t2(s) * (1 - self.calc_P1(s)) * (1 - self.calc_u(s))

    def calc_process3(self, s):
        """
        Calculate the probability that process 3 is successful
        """
        t3 = (1 / self.f(s) - 0.5) * self.c3 + self.calc_t2(s)
        return t3 * (1 - self.calc_P1(s)) * self.calc_u(s)

    def calc_TTC(self, attacker_skill):
        """
        Calculate the Time to Compromise (TTC)

        Returns:
            float: The calculated TTC
        """
        t1 = self.calc_t1()
        P1 = self.calc_P1(attacker_skill)
        t2 = float(self.c2(attacker_skill) * 10 / (self.max_exploitability))
        u = self.calc_u(attacker_skill)
        t3 = (1 / self.f(attacker_skill) - 0.5) * self.c3 + t2
        ttc = t1 * P1 + t2 * (1 - P1) * (1 - u) + t3 * (1 - P1) * u
        return ttc

    def calc_TTC_components(self, attacker_skill):
        """
        Calculate the Time to Compromise (TTC) and its components

        Returns:
            dict: The calculated TTC and its components
        """
        t1 = self.calc_t1()
        P1 = self.calc_P1(attacker_skill)
        t2 = float(self.c2(attacker_skill) * 10 / float((self.max_exploitability)))
        u = self.calc_u(attacker_skill)
        t3 = (1 / self.f(attacker_skill) - 0.5) * self.c3 + t2
        process1 = t1 * P1
        process2 = t2 * (1 - P1) * (1 - u)
        process3 = t3 * (1 - P1) * u
        ttc = process1 + process2 + process3
        ttc_dict = {
            "TTC": ttc,
            "t1": t1,
            "P1": P1,
            "t2": t2,
            "u": u,
            "t3": t3,
        }
        return ttc_dict
