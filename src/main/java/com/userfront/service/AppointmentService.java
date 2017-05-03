package com.userfront.service;


import com.userfront.domain.Appointment;

import java.util.List;

public interface AppointmentService {

    Appointment createAppointment(Appointment appointment);

    List<Appointment> findAll();

    void confirmAppointment(Long id);
}
