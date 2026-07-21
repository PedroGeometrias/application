package com.pedroharo.threatlens.domain;

import java.util.List;

public record RiskAssessment(int score, RiskVerdict verdict, List<String> reasons) {}
