
package com.cybershield.model;

public enum Severity {

    LOW(1),
    MEDIUM(3),
    HIGH(7),
    CRITICAL(15);

    private final int weight;

    Severity(int weight) {
        this.weight = weight;
    }

    public int getWeight() {
        return weight;
    }
}

