/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   Normalizer.h
 * Author: francesco
 *
 * Created on May 10, 2017, 10:22 PM
 */

#pragma once

#ifndef NORMALIZER_H
#define NORMALIZER_H

#include <cstdint>
#include <netinet/ip.h>

class NormalizeManager {
public:
    NormalizeManager();
    virtual ~NormalizeManager();
    
    bool clean(const u_int64_t * techVector, ip* ip_packet);
    
private:

};

#endif /* NORMALIZER_H */

